package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.llm.HttpAnomalyDetector;
import ru.galkov.util.*;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

import static ru.galkov.Main.getConfig;
import static ru.galkov.util.IoUtil.closeQuietly;

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
    private final Semaphore connectionSlots;
    private final ClientCounterMap connectionsByClient = new ClientCounterMap();
    private final Set<Socket> activeClientSockets = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<Socket, ConnectionLease> leasesBySocket = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Socket, Long> socketActivity = new ConcurrentHashMap<>();
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
        if (maxConnectionsPerClient > maxConnections)
            throw new IllegalArgumentException("max-connections-per-client <= max-connections");

        this.connectionSlots = new Semaphore(maxConnections, true);
    }

    public void start() {
        synchronized (lifecycleLock) {
            if (running) {
                logger.warn("Прокси сервер уже запущен на порту {}", port);
                return;
            }

            running = true;

            logger.info(
                    "Инициализация HTTP proxy: " +
                            "port={}, maxConnections={}, " +
                            "maxConnectionsPerClient={}, " +
                            "maxActiveSockets={}",
                    port,
                    maxConnections,
                    maxConnectionsPerClient,
                    maxActiveSockets
            );

            serverThread =
                    new NamedThreadFactory(
                            "HttpProxy-Server-Thread-" + port,
                            false
                    ).newThread(this::runServer);

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
            leasesBySocket.values().forEach(ConnectionLease::release);
            leasesBySocket.clear();
            activeClientSockets.forEach(IoUtil::closeQuietly);
            activeClientSockets.clear();
            socketActivity.clear();
        }

        joinServerThread();
        logAggregatedStatistics();
        logger.info("Остановка HTTP proxy завершена: port={}", port);
    }

    private void runServer() {
        try (ServerSocket localServerSocket = new ServerSocket(port)) {
            serverSocket = localServerSocket;
            logger.info("HTTP Proxy слушает порт {}", port);
            while (running) {
                Socket clientSocket;
                try {
                    clientSocket = localServerSocket.accept();
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
            if (running) {
                logger.error("Не удалось запустить HTTP Proxy на порту {}", port, e);
            } else {
                logger.info("HTTP Proxy остановлен на порту {}", port);
            }
        } finally {
            serverSocket = null;
            running = false;
            leasesBySocket.values().forEach(ConnectionLease::release);
            leasesBySocket.clear();
            activeClientSockets.clear();
            socketActivity.clear();
            logAggregatedStatistics();
            logger.info("HTTP Proxy server thread завершён");
        }
    }

    private void handleAcceptedConnection(
            Socket clientSocket
    ) {
        String clientIp =
                clientSocket.getInetAddress() == null ? "unknown" : clientSocket.getInetAddress().getHostAddress();

        if (!activeClientSockets.add(clientSocket)) {
            duplicateSocketCount.increment();
            closeQuietly(clientSocket);
            cleanupOldSockets();
            return;
        }

        socketActivity.put(clientSocket, System.currentTimeMillis());

        if (activeClientSockets.size() > maxActiveSockets) {
            removeSocketBookkeeping(clientSocket);
            maxSocketsRejectedCount.increment();
            closeQuietly(clientSocket);
            cleanupOldSockets();
            return;
        }

        if (!connectionSlots.tryAcquire()) {
            removeSocketBookkeeping(clientSocket);
            maxConnectionsRejectedCount.increment();
            closeQuietly(clientSocket);
            return;
        }

        ConnectionLease lease = null;

        try {
            AtomicInteger clientCounter = connectionsByClient.getOrCreate(clientIp);
            int activeForClient = clientCounter.incrementAndGet();
            if (activeForClient > maxConnectionsPerClient) {
                connectionsByClient.decrementAndRemoveIfZero(clientIp, clientCounter);
                connectionSlots.release();
                removeSocketBookkeeping(clientSocket);
                maxClientConnectionsRejectedCount.increment();
                closeQuietly(clientSocket);
                return;
            }

            lease =
                    ConnectionLease.fromReserved(
                            clientSocket,
                            clientIp,
                            connectionsByClient,
                            clientCounter,
                            connectionSlots
                    );

            if (leasesBySocket.putIfAbsent(clientSocket, lease) != null) {
                duplicateSocketCount.increment();
                removeSocketBookkeeping(clientSocket);
                lease.release();
                return;
            }

            ConnectionLease submittedLease = lease;
            WorkerPool.SubmitResult submitResult =
                    WorkerPool.submit(
                            () -> {
                                try {
                                    new ProxyHandler(submittedLease, blacklist, httpAnomalyDetector).run();
                                } finally {
                                    removeSocketBookkeeping(submittedLease.socket());
                                    leasesBySocket.remove(submittedLease.socket(), submittedLease);
                                    submittedLease.release();
                                }
                            }
                    );

            if (submitResult != WorkerPool.SubmitResult.ACCEPTED) {
                workerPoolRejectedCount.increment();
                leasesBySocket.remove(clientSocket, lease);
                removeSocketBookkeeping(clientSocket);
                lease.release();
            }
        } catch (RuntimeException e) {
            workerPoolRejectedCount.increment();
            if (lease != null) {
                leasesBySocket.remove(clientSocket, lease);
                lease.release();
            } else {
                connectionSlots.release();
            }

            removeSocketBookkeeping(clientSocket);
            closeQuietly(clientSocket);
            logger.error("Не удалось передать соединение в worker pool: client={}", clientIp, e);
        }
    }

    private void removeSocketBookkeeping(Socket socket) {
        activeClientSockets.remove(socket);
        socketActivity.remove(socket);
    }

    private void cleanupOldSockets() {
        int currentSize = activeClientSockets.size();
        if (currentSize < maxActiveSockets) return;
        int configured = getConfig().getInt("proxy.cleanup-sockets-per-iteration");
        int toRemoveCount = configured > 0 ? configured : 10;
        long now = System.currentTimeMillis();
        List<Socket> idleSockets = new ArrayList<>(toRemoveCount);

        for (Socket socket : activeClientSockets) {
            if (idleSockets.size() >= toRemoveCount) break;
            Long lastActivity = socketActivity.get(socket);
            if (lastActivity == null || now - lastActivity > idleCleanupThresholdMillis) idleSockets.add(socket);
        }

        for (Socket socket : idleSockets) {
            ConnectionLease lease = leasesBySocket.get(socket);

            if (lease != null) {
                lease.release();
                leasesBySocket.remove(socket, lease);
            } else {
                closeQuietly(socket);
            }

            removeSocketBookkeeping(socket);
        }

        if (!idleSockets.isEmpty()) {
            cleanedSocketsCount.add(idleSockets.size());
            int removedPercent = idleSockets.size() * 100 / Math.max(1, currentSize);
            logger.info(
                    LocaleUtil.getString(
                            "http_proxy_socket_cleanup_triggered"
                    ),
                    idleSockets.size(),
                    removedPercent,
                    currentSize
            );
        }
    }

    private void joinServerThread() {
        Thread thread = serverThread;
        if (thread == null || thread == Thread.currentThread()) return;
        try {
            thread.join(5000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void waitForSocketReady() {
        long timeout = System.currentTimeMillis() + 5000L;

        while (System.currentTimeMillis() < timeout) {
            if (serverSocket != null && serverSocket.isBound() && !serverSocket.isClosed()) return;

            try {
                Thread.sleep(50L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
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

        if (
                duplicateSockets == 0
                        && maxSocketsRejected == 0
                        && maxConnectionsRejected == 0
                        && maxClientConnectionsRejected == 0
                        && acceptSocketErrors == 0
                        && acceptIoErrors == 0
                        && workerPoolRejected == 0
                        && cleanedSockets == 0
        ) {
            return;
        }

        logger.debug(
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