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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

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
    private final int maxActiveSockets;

    private final ExecutorService workerPool;
    private final Semaphore connectionSlots;
    private final ConcurrentMap<String, AtomicInteger> connectionsByClient = new ConcurrentHashMap<>();
    private final Set<Socket> activeClientSockets = ConcurrentHashMap.newKeySet();

    private final ConcurrentMap<Socket, Long> socketActivity = new ConcurrentHashMap<>();
    private final long idleCleanupThresholdMillis;

    private final Object lifecycleLock = new Object();
    private volatile boolean running;
    private volatile ServerSocket serverSocket;
    private volatile Thread serverThread;

    private final LongAdder maxSocketsRejectedCount = new LongAdder();
    private final LongAdder maxConnectionsRejectedCount = new LongAdder();
    private final LongAdder maxClientConnectionsRejectedCount = new LongAdder();
    private final LongAdder acceptSocketErrorsCount = new LongAdder();
    private final LongAdder acceptIoErrorsCount = new LongAdder();
    private final LongAdder workerPoolRejectedCount = new LongAdder();
    private final LongAdder duplicateSocketCount = new LongAdder();
    private final LongAdder cleanedSocketsCount = new LongAdder();

    public HttpProxyServer(int port, BlacklistLoader blacklist, HttpAnomalyDetector httpAnomalyDetector) {
        this.port = port;
        this.blacklist = Objects.requireNonNull(blacklist);
        this.httpAnomalyDetector = httpAnomalyDetector;
        this.maxConnections = getConfig().getInt("proxy.max-connections");
        this.maxConnectionsPerClient = getConfig().getInt("proxy.max-connections-per-client");

        int multiplier = getConfig().getInt("proxy.max-active-sockets-multiplier");
        this.maxActiveSockets = maxConnections * (multiplier > 0 ? multiplier : 2);

        int idleSec = getConfig().getInt("proxy.idle-socket-timeout-seconds");
        this.idleCleanupThresholdMillis = (idleSec > 0 ? idleSec : 30) * 1000L;

        if (maxConnections <= 0) throw new IllegalArgumentException("proxy.max-connections > 0");
        if (maxConnectionsPerClient <= 0) throw new IllegalArgumentException("proxy.max-connections-per-client > 0");
        if (maxConnectionsPerClient > maxConnections) throw new IllegalArgumentException("max-connections-per-client <= max-connections");

        this.connectionSlots = new Semaphore(maxConnections, true);
        this.workerPool = WorkerPool.get();
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
            socketActivity.clear();
        }
        joinServerThread();
        logAggregatedStatistics();
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
                    acceptSocketErrorsCount.increment();
                    continue;
                } catch (IOException e) {
                    if (!running) break;
                    acceptIoErrorsCount.increment();
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
            logAggregatedStatistics();
            logger.info("HTTP Proxy server thread завершён");
        }
    }

    private void handleAcceptedConnection(Socket clientSocket) {
        String clientIp = clientSocket.getInetAddress().getHostAddress();

        // ✅ П.55: атомарная проверка и добавление
        if (!activeClientSockets.add(clientSocket)) {
            duplicateSocketCount.increment();
            closeQuietly(clientSocket);
            cleanupOldSockets();
            return;
        }

        socketActivity.put(clientSocket, System.currentTimeMillis());

        if (activeClientSockets.size() > maxActiveSockets) {
            activeClientSockets.remove(clientSocket);
            socketActivity.remove(clientSocket);
            maxSocketsRejectedCount.increment();
            closeQuietly(clientSocket);
            cleanupOldSockets();
            return;
        }

        if (!connectionSlots.tryAcquire()) {
            activeClientSockets.remove(clientSocket);
            socketActivity.remove(clientSocket);
            maxConnectionsRejectedCount.increment();
            closeQuietly(clientSocket);
            return;
        }

        AtomicInteger clientConnections = connectionsByClient.computeIfAbsent(clientIp, k -> new AtomicInteger());
        if (clientConnections == null) {
            activeClientSockets.remove(clientSocket);
            socketActivity.remove(clientSocket);
            connectionSlots.release();
            logger.error("computeIfAbsent вернул null для client={}", clientIp);
            closeQuietly(clientSocket);
            return;
        }

        int activeForClient = clientConnections.incrementAndGet();

        if (activeForClient > maxConnectionsPerClient) {
            activeClientSockets.remove(clientSocket);
            socketActivity.remove(clientSocket);
            releaseConnectionSlot(clientIp, clientConnections);
            maxClientConnectionsRejectedCount.increment();
            closeQuietly(clientSocket);
            return;
        }

        try {
            workerPool.execute(() -> {
                try {
                    new ProxyHandler(clientSocket, clientIp, blacklist, httpAnomalyDetector).run();
                } finally {
                    activeClientSockets.remove(clientSocket);
                    socketActivity.remove(clientSocket);
                    releaseConnectionSlot(clientIp, clientConnections);
                }
            });
        } catch (RuntimeException e) {
            activeClientSockets.remove(clientSocket);
            socketActivity.remove(clientSocket);
            releaseConnectionSlot(clientIp, clientConnections);
            closeQuietly(clientSocket);
            workerPoolRejectedCount.increment();
            logger.error("Не удалось передать соединение в worker pool: client={}", clientIp, e);
        }
    }

    private void cleanupOldSockets() {
        int currentSize = activeClientSockets.size();
        if (currentSize < maxActiveSockets) {
            return;
        }

        int toRemoveCount = getConfig().getInt("proxy.cleanup-sockets-per-iteration");
        long now = System.currentTimeMillis();
        int removed = 0;

        List<Socket> idleSockets = new ArrayList<>(toRemoveCount);
        for (Socket socket : activeClientSockets) {
            if (idleSockets.size() >= toRemoveCount) break;

            Long lastActivity = socketActivity.get(socket);
            if (lastActivity == null
                    || (now - lastActivity) > idleCleanupThresholdMillis) {
                idleSockets.add(socket);
            }
        }

        for (Socket socket : idleSockets) {
            if (socket != null && !socket.isClosed()) {
                closeQuietly(socket);
            }
            activeClientSockets.remove(socket);
            socketActivity.remove(socket);
            removed++;
        }

        if (removed > 0) {
            cleanedSocketsCount.add(removed);
            int removedPercent = (removed * 100) / currentSize;
            logger.info(LocaleUtil.getString("http_proxy_socket_cleanup_triggered"),
                    removed, removedPercent, currentSize);
        }
    }

    private void releaseConnectionSlot(String clientIp, AtomicInteger clientConnections) {
        int remaining = clientConnections.decrementAndGet();
        if (remaining <= 0) connectionsByClient.remove(clientIp, clientConnections);
        connectionSlots.release();
    }

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

    private void logAggregatedStatistics() {
        long duplicateSockets = duplicateSocketCount.sum();
        long maxSocketsRejected = maxSocketsRejectedCount.sum();
        long maxConnectionsRejected = maxConnectionsRejectedCount.sum();
        long maxClientConnectionsRejected = maxClientConnectionsRejectedCount.sum();
        long acceptSocketErrors = acceptSocketErrorsCount.sum();
        long acceptIoErrors = acceptIoErrorsCount.sum();
        long workerPoolRejected = workerPoolRejectedCount.sum();
        long cleanedSockets = cleanedSocketsCount.sum();

        if (duplicateSockets == 0
                && maxSocketsRejected == 0
                && maxConnectionsRejected == 0
                && maxClientConnectionsRejected == 0
                && acceptSocketErrors == 0
                && acceptIoErrors == 0
                && workerPoolRejected == 0
                && cleanedSockets == 0) {
            return;
        }

        logger.info(
                "HTTP Proxy aggregated statistics: " +
                        "duplicateSockets={}, " +
                        "maxSocketsRejected={}, " +
                        "maxConnectionsRejected={}, " +
                        "maxClientConnectionsRejected={}, " +
                        "acceptSocketErrors={}, " +
                        "acceptIoErrors={}, " +
                        "workerPoolRejected={}, " +
                        "cleanedSockets={}",
                duplicateSockets,
                maxSocketsRejected,
                maxConnectionsRejected,
                maxClientConnectionsRejected,
                acceptSocketErrors,
                acceptIoErrors,
                workerPoolRejected,
                cleanedSockets
        );
    }
}