package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.BlacklistLoader;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class HttpProxyServer {

    private static final Logger logger =
            LoggerFactory.getLogger(HttpProxyServer.class);

    private final BlacklistLoader blacklist;
    private final int port;
    private final ExecutorService workerPool;

    private final int maxConnections;
    private final int maxConnectionsPerClient;

    private final Semaphore connectionSlots;
    private final ConcurrentHashMap<String, AtomicInteger> connectionsByClient =
            new ConcurrentHashMap<String, AtomicInteger>();

    private volatile boolean running;
    private Thread serverThread;

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
        if (running) {
            logger.warn("Прокси сервер уже запущен на порту {}", Optional.of(port));
            return;
        }

        running = true;

        logger.info(
                "Инициализация HTTP proxy: port={}, maxConnections={}, maxConnectionsPerClient={}",
                port,
                maxConnections,
                maxConnectionsPerClient
        );

        serverThread = new Thread(this::runServer, "HttpProxy-Server-Thread-" + port);
        serverThread.setDaemon(false);
        serverThread.start();
        waitForSocketReady();
    }

    private void runServer() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("HTTP Proxy успешно начал слушать порт {}", port);

            while (running) {
                Socket clientSocket;

                try {
                    clientSocket = serverSocket.accept();
                } catch (IOException e) {
                    if (!running) {
                        logger.debug("Приём соединений прокси остановлен корректно");
                        break;
                    }

                    logger.error("Ошибка при попытке принять соединение на порту {}", port, e);
                    continue;
                }
                handleAcceptedConnection(clientSocket);
            }

        } catch (IOException e) {
            if (running) {
                logger.error("Не удалось запустить HTTP Proxy на порту {}. Порт занят или нет прав доступа.", port, e);
            } else
                logger.info("HTTP Proxy корректно остановлен на порту {}", port);


        } finally {
            workerPool.shutdown();
            logger.info("Пул потоков proxy-сервера остановлен");
        }
    }

    private void handleAcceptedConnection(Socket clientSocket) {
        String clientIp = clientSocket.getInetAddress().getHostAddress();

        if (!connectionSlots.tryAcquire()) {
            logger.warn(
                    "PROXY_CONNECTION_REJECT client={} reason=MAX_CONNECTIONS " +
                            "active={} limit={}",
                    clientIp,
                    maxConnections - connectionSlots.availablePermits(),
                    maxConnections
            );

            closeQuietly(clientSocket);
            return;
        }

        AtomicInteger clientConnections =
                connectionsByClient.computeIfAbsent(clientIp, key -> new AtomicInteger());

        int activeForClient = clientConnections.incrementAndGet();

        if (activeForClient > maxConnectionsPerClient) {
            releaseConnectionSlot(clientIp, clientConnections);

            logger.warn(
                    "PROXY_CONNECTION_REJECT client={} " +
                            "reason=MAX_CONNECTIONS_PER_CLIENT " +
                            "activeForClient={} limit={}",
                    clientIp,
                    activeForClient,
                    maxConnectionsPerClient
            );

            closeQuietly(clientSocket);
            return;
        }

        logger.debug(
                "PROXY_CONNECTION_ACCEPT client={} active={} activeForClient={}",
                clientIp,
                maxConnections - connectionSlots.availablePermits(),
                activeForClient
        );

        try {
            workerPool.execute(
                    () -> {
                        try {
                            new ProxyHandler(clientSocket, clientIp, blacklist).run();
                        } finally {
                            releaseConnectionSlot(clientIp, clientConnections);
                        }
                    }
            );

        } catch (RuntimeException e) {
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
        logger.debug(
                "PROXY_CONNECTION_CLOSE client={} active={} activeForClient={}",
                clientIp,
                maxConnections - connectionSlots.availablePermits(),
                Math.max(remaining, 0)
        );
    }

    private void validateLimits() {
        if (maxConnections <= 0)
            throw new IllegalArgumentException("proxy.max-connections должен быть больше 0");
        if (maxConnectionsPerClient <= 0)
            throw new IllegalArgumentException("proxy.max-connections-per-client должен быть больше 0");
        if (maxConnectionsPerClient > maxConnections)
            throw new IllegalArgumentException("proxy.max-connections-per-client не может быть больше proxy.max-connections");

    }

    private void closeQuietly(Socket socket) {
        if (socket == null) return;

        try {
            socket.close();
        } catch (IOException e) {
            logger.debug("Ошибка закрытия отклонённого proxy-соединения: {}", e.getMessage());
        }
    }

    private void waitForSocketReady() {
        long timeout = System.currentTimeMillis() + 5000L;

        while (System.currentTimeMillis() < timeout) {
            try {
                Thread.sleep(100L);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }
}