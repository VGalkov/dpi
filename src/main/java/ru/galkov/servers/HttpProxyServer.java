package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.BlacklistLoader;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class HttpProxyServer {

    private static final Logger logger = LoggerFactory.getLogger(HttpProxyServer.class);

    private final BlacklistLoader blacklist;
    private final int port;
    private final ExecutorService workerPool;

    private final int maxConnections;
    private final int maxConnectionsPerClient;

    private final Semaphore connectionSlots;
    private final ConcurrentMap<String, AtomicInteger> connectionsByClient =
            new ConcurrentHashMap<String, AtomicInteger>();

    private final Set<Socket> activeClientSockets =
            ConcurrentHashMap.newKeySet();

    private final Object lifecycleLock = new Object();

    private volatile boolean running;
    private volatile ServerSocket serverSocket;
    private volatile Thread serverThread;

    public HttpProxyServer(int port, BlacklistLoader blacklist) {
        this.port = port;
        this.blacklist = Objects.requireNonNull(blacklist);
        this.maxConnections = getConfig().getInt("proxy.max-connections");
        this.maxConnectionsPerClient = getConfig().getInt("proxy.max-connections-per-client");

        validateLimits();

        this.connectionSlots = new Semaphore(maxConnections, true);
        this.workerPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
    }

    public void start() {
        synchronized (lifecycleLock) {
            if (running) {
                logger.warn("Прокси сервер уже запущен на порту {}", Optional.of(port));
                return;
            }

            running = true;

            logger.info("Инициализация HTTP proxy: port={}, maxConnections={}, maxConnectionsPerClient={}",
                    port, maxConnections, maxConnectionsPerClient);

            serverThread = new Thread(this::runServer, "HttpProxy-Server-Thread-" + port);
            serverThread.setDaemon(false);
            serverThread.start();
        }

        waitForSocketReady();
    }

    public void stop() {
        synchronized (lifecycleLock) {
            if (!running) return;
            logger.info("Остановка HTTP proxy начата: port={}", port);
            running = false;
            closeQuietly(serverSocket);
            for (Socket clientSocket : activeClientSockets)
                closeQuietly(clientSocket);
        }

        shutdownWorkerPool();
        joinServerThread();
        logger.info("Остановка HTTP proxy завершена: port={}", port);
    }

    private void runServer() {
        try (ServerSocket localServerSocket = new ServerSocket(port)) {
            serverSocket = localServerSocket;
            logger.info("HTTP Proxy успешно начал слушать порт {}", port);

            while (running) {
                Socket clientSocket;

                try {
                    clientSocket = localServerSocket.accept();

                } catch (SocketException e) {
                    if (!running) break;
                    logger.warn("Ошибка accept HTTP proxy: {}", e.getMessage());
                    continue;

                } catch (IOException e) {
                    if (!running) break;
                    logger.error("Ошибка при попытке принять соединение на порту {}", port, e);
                    continue;
                }

                if (!running) {
                    closeQuietly(clientSocket);
                    break;
                }

                handleAcceptedConnection(clientSocket);
            }

        } catch (IOException e) {
            if (running) {
                logger.error("Не удалось запустить HTTP Proxy на порту {}. Порт занят или нет прав доступа.", port, e);
            } else {
                logger.info("HTTP Proxy корректно остановлен на порту {}", port);
            }

        } finally {
            serverSocket = null;
            running = false;

            shutdownWorkerPool();

            logger.info("HTTP Proxy server thread завершён");
        }
    }

    private void handleAcceptedConnection(Socket clientSocket) {
        String clientIp = clientSocket.getInetAddress().getHostAddress();

        if (!connectionSlots.tryAcquire()) {
            logger.warn("PROXY_CONNECTION_REJECT client={} reason=MAX_CONNECTIONS active={} limit={}",
                    clientIp, maxConnections - connectionSlots.availablePermits(), maxConnections);

            closeQuietly(clientSocket);
            return;
        }

        AtomicInteger clientConnections = connectionsByClient.computeIfAbsent(clientIp, key -> new AtomicInteger());
        int activeForClient = clientConnections.incrementAndGet();
        if (activeForClient > maxConnectionsPerClient) {
            releaseConnectionSlot(clientIp, clientConnections);
            logger.warn("PROXY_CONNECTION_REJECT client={} reason=MAX_CONNECTIONS_PER_CLIENT activeForClient={} limit={}",
                    clientIp, activeForClient, maxConnectionsPerClient);
            closeQuietly(clientSocket);
            return;
        }

        activeClientSockets.add(clientSocket);

        logger.debug("PROXY_CONNECTION_ACCEPT client={} active={} activeForClient={}",
                clientIp, maxConnections - connectionSlots.availablePermits(), activeForClient);

        try {
            workerPool.execute(() -> {
                try {
                    new ProxyHandler(clientSocket, clientIp, blacklist).run();

                } finally {
                    activeClientSockets.remove(clientSocket);
                    releaseConnectionSlot(clientIp, clientConnections);
                }
            });

        } catch (RuntimeException e) {
            activeClientSockets.remove(clientSocket);
            releaseConnectionSlot(clientIp, clientConnections);
            closeQuietly(clientSocket);

            logger.error("Не удалось передать proxy-соединение в worker pool: client={}", clientIp, e);
        }
    }

    private void releaseConnectionSlot(String clientIp, AtomicInteger clientConnections) {
        int remaining = clientConnections.decrementAndGet();

        if (remaining <= 0)
            connectionsByClient.remove(clientIp, clientConnections);
        connectionSlots.release();
        logger.debug("PROXY_CONNECTION_CLOSE client={} active={} activeForClient={}",
                clientIp, maxConnections - connectionSlots.availablePermits(), Math.max(remaining, 0));
    }

    private void shutdownWorkerPool() {
        workerPool.shutdown();

        try {
            if (!workerPool.awaitTermination(10, TimeUnit.SECONDS)) {
                logger.warn("Proxy worker pool не завершился за 10 секунд, выполняется shutdownNow");
                workerPool.shutdownNow();
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            workerPool.shutdownNow();
        }
    }

    private void joinServerThread() {
        Thread currentServerThread = serverThread;
        if (currentServerThread == null || currentServerThread == Thread.currentThread())
            return;
        try {
            currentServerThread.join(5000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void validateLimits() {
        if (maxConnections <= 0)
            throw new IllegalArgumentException("proxy.max-connections должен быть больше 0");
        if (maxConnectionsPerClient <= 0)
            throw new IllegalArgumentException("proxy.max-connections-per-client должен быть больше 0");
        if (maxConnectionsPerClient > maxConnections)
            throw new IllegalArgumentException("proxy.max-connections-per-client не может быть больше proxy.max-connections");
    }

    private void closeQuietly(ServerSocket socket) {
        if (socket == null || socket.isClosed()) {
            return;
        }

        try {
            socket.close();

        } catch (IOException e) {
            logger.debug("Ошибка закрытия HTTP proxy listener: {}", e.getMessage());
        }
    }

    private void closeQuietly(Socket socket) {
        if (socket == null || socket.isClosed()) {
            return;
        }

        try {
            socket.close();

        } catch (IOException e) {
            logger.debug("Ошибка закрытия proxy socket: {}", e.getMessage());
        }
    }

    private void waitForSocketReady() {
        long timeout = System.currentTimeMillis() + 5000L;

        while (System.currentTimeMillis() < timeout) {
            if (serverSocket != null && serverSocket.isBound() && !serverSocket.isClosed()) {
                return;
            }

            try {
                Thread.sleep(50L);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }

        logger.warn("HTTP Proxy не подтвердил открытие порта {} за 5 секунд", port);
    }
}