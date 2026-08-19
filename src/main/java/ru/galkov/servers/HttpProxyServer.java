package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.llm.HttpAnomalyDetector;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.LocaleUtil;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class HttpProxyServer {
    private static final Logger logger = LoggerFactory.getLogger(HttpProxyServer.class);

    private final BlacklistLoader blacklist;
    private final HttpAnomalyDetector httpAnomalyDetector;
    private final int port;
    private final int maxConnections;
    private final int maxConnectionsPerClient;
    private final int maxActiveSockets;  // ✅ П.10: новый лимит

    private final ExecutorService workerPool;
    private final Semaphore connectionSlots;
    private final ConcurrentMap<String, AtomicInteger> connectionsByClient = new ConcurrentHashMap<>();
    private final Set<Socket> activeClientSockets = ConcurrentHashMap.newKeySet();

    private final Object lifecycleLock = new Object();
    private volatile boolean running;
    private volatile ServerSocket serverSocket;
    private volatile Thread serverThread;

    public HttpProxyServer(int port, BlacklistLoader blacklist, HttpAnomalyDetector httpAnomalyDetector) {
        this.port = port;
        this.blacklist = Objects.requireNonNull(blacklist);
        this.httpAnomalyDetector = httpAnomalyDetector;
        this.maxConnections = getConfig().getInt("proxy.max-connections");
        this.maxConnectionsPerClient = getConfig().getInt("proxy.max-connections-per-client");
        this.maxActiveSockets = maxConnections * 2;  // ✅ П.10: лимит = 2 × max-connections

        if (maxConnections <= 0) throw new IllegalArgumentException("proxy.max-connections > 0");
        if (maxConnectionsPerClient <= 0) throw new IllegalArgumentException("proxy.max-connections-per-client > 0");
        if (maxConnectionsPerClient > maxConnections) throw new IllegalArgumentException("max-connections-per-client <= max-connections");

        this.connectionSlots = new Semaphore(maxConnections, true);
        this.workerPool = WorkerPool.get();  // ✅ П.26: общий worker pool
    }

    public void start() {
        synchronized (lifecycleLock) {
            if (running) {
                logger.warn("Прокси сервер уже запущен на порту {}", port);
                return;
            }
            running = true;
            logger.info("Инициализация HTTP proxy: port={}, maxConnections={}, maxConnectionsPerClient={}, maxActiveSockets={}",
                    port, maxConnections, maxConnectionsPerClient, maxActiveSockets);
            serverThread = new Thread(this::runServer, "HttpProxy-Server-Thread-" + port);
            serverThread.setDaemon(false);
            serverThread.start();
        }
        waitForSocketReady();
    }

    public void stop() {
        synchronized (lifecycleLock) {
            if (!running) return;
            logger.info("Остановка HTTP proxy: port={}", port);
            running = false;
            closeQuietly(serverSocket);
            activeClientSockets.forEach(this::closeQuietly);
            activeClientSockets.clear();
        }
        // ✅ П.26: не закрываем общий worker pool
        joinServerThread();
        logger.info("Остановка HTTP proxy завершена: port={}", port);
    }

    private void runServer() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            this.serverSocket = serverSocket;
            logger.info("HTTP Proxy слушает порт {}", port);

            while (running) {
                Socket clientSocket;
                try {
                    clientSocket = serverSocket.accept();
                } catch (SocketException e) {
                    if (!running) break;
                    logger.warn("Ошибка accept: {}", e.getMessage());
                    continue;
                } catch (IOException e) {
                    if (!running) break;
                    logger.error("Ошибка accept на порту {}", port, e);
                    continue;
                }

                if (!running) {
                    closeQuietly(clientSocket);
                    break;
                }
                handleAcceptedConnection(clientSocket);
            }
        } catch (IOException e) {
            if (running) logger.error("Не удалось запустить HTTP Proxy на порту {}", port, e);
            else logger.info("HTTP Proxy остановлен на порту {}", port);
        } finally {
            this.serverSocket = null;
            running = false;
            // ✅ П.26: не закрываем общий worker pool
            logger.info("HTTP Proxy server thread завершён");
        }
    }

    /**
     * ✅ П.10: Ограничение на activeClientSockets
     */
    private void handleAcceptedConnection(Socket clientSocket) {
        String clientIp = clientSocket.getInetAddress().getHostAddress();

        // ✅ П.10: Проверка на максимальное количество сокетов
        if (activeClientSockets.size() >= maxActiveSockets) {
            logger.warn(LocaleUtil.getString("http_proxy_max_sockets_reached"), activeClientSockets.size(), maxActiveSockets);
            closeQuietly(clientSocket);
            cleanupOldSockets();  // ✅ Очистка старых сокетов
            return;
        }

        if (!connectionSlots.tryAcquire()) {
            logger.warn("PROXY_CONNECTION_REJECT client={} reason=MAX_CONNECTIONS", clientIp);
            closeQuietly(clientSocket);
            return;
        }

        AtomicInteger clientConnections = connectionsByClient.computeIfAbsent(clientIp, k -> new AtomicInteger());
        int activeForClient = clientConnections.incrementAndGet();

        if (activeForClient > maxConnectionsPerClient) {
            releaseConnectionSlot(clientIp, clientConnections);
            logger.warn("PROXY_CONNECTION_REJECT client={} reason=MAX_CONNECTIONS_PER_CLIENT", clientIp);
            closeQuietly(clientSocket);
            return;
        }

        activeClientSockets.add(clientSocket);
        logger.debug("PROXY_CONNECTION_ACCEPT client={} activeForClient={}", clientIp, activeForClient);

        try {
            workerPool.execute(() -> {
                try {
                    new ProxyHandler(clientSocket, clientIp, blacklist, httpAnomalyDetector).run();
                } finally {
                    activeClientSockets.remove(clientSocket);
                    releaseConnectionSlot(clientIp, clientConnections);
                }
            });
        } catch (RuntimeException e) {
            activeClientSockets.remove(clientSocket);
            releaseConnectionSlot(clientIp, clientConnections);
            closeQuietly(clientSocket);
            logger.error("Не удалось передать соединение в worker pool: client={}", clientIp, e);
        }
    }

    /**
     * ✅ П.10: Очистка старых сокетов при переполнении
     */
    private void cleanupOldSockets() {
        int removed = 0;
        for (Socket socket : activeClientSockets) {
            if (activeClientSockets.size() < maxActiveSockets) break;
            if (socket != null && !socket.isClosed()) {
                closeQuietly(socket);
                activeClientSockets.remove(socket);
                removed++;
            }
        }
        if (removed > 0) {
            logger.info(LocaleUtil.getString("http_proxy_socket_cleaned"), removed);
        }
    }

    private void releaseConnectionSlot(String clientIp, AtomicInteger clientConnections) {
        int remaining = clientConnections.decrementAndGet();
        if (remaining <= 0) connectionsByClient.remove(clientIp, clientConnections);
        connectionSlots.release();
        logger.debug("PROXY_CONNECTION_CLOSE client={} activeForClient={}", clientIp, Math.max(remaining, 0));
    }

    // ✅ П.26: удалён метод shutdownWorkerPool()

    private void joinServerThread() {
        Thread t = serverThread;
        if (t == null || t == Thread.currentThread()) return;
        try { t.join(5000L); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private void closeQuietly(ServerSocket s) {
        if (s != null && !s.isClosed()) {
            try { s.close(); } catch (IOException e) { logger.debug("Ошибка закрытия server socket: {}", e.getMessage()); }
        }
    }

    private void closeQuietly(Socket s) {
        if (s != null && !s.isClosed()) {
            try { s.close(); } catch (IOException e) { logger.debug("Ошибка закрытия socket: {}", e.getMessage()); }
        }
    }

    private void waitForSocketReady() {
        long timeout = System.currentTimeMillis() + 5000L;
        while (System.currentTimeMillis() < timeout) {
            if (serverSocket != null && serverSocket.isBound() && !serverSocket.isClosed()) return;
            try { Thread.sleep(50L); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
        }
        logger.warn("HTTP Proxy не открыл порт {} за 5 секунд", port);
    }
}