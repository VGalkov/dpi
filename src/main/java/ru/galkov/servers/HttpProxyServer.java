package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.llm.HttpAnomalyDetector;
import ru.galkov.util.*;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

import static ru.galkov.Main.getConfig;
import static ru.galkov.util.IoUtil.closeQuietly;

public class HttpProxyServer {

    private static final Logger logger = LoggerFactory.getLogger(HttpProxyServer.class);
    private final Set<Integer> ports;
    private final Set<Integer> transparentPorts;
    private final BlacklistLoader blacklist;
    private final HttpAnomalyDetector httpAnomalyDetector;
    private final int maxConnections;
    private final int maxConnectionsPerClient;
    private final int maxActiveSockets;
    private final Semaphore connectionSlots;
    private final ClientCounterMap connectionsByClient = new ClientCounterMap();
    private final Set<Socket> activeClientSockets = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<Socket, ConnectionLease> leasesBySocket = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Socket, Long> socketActivity = new ConcurrentHashMap<>();
    private final long idleCleanupThresholdMillis;
    private volatile boolean running;
    private final Map<Integer, ServerSocket> serverSockets = new ConcurrentHashMap<>();
    private final List<Thread> serverThreads = new ArrayList<>();
    private final LongAdder maxSocketsRejectedCount = new LongAdder();
    private final LongAdder maxConnectionsRejectedCount = new LongAdder();
    private final LongAdder maxClientConnectionsRejectedCount = new LongAdder();
    private final LongAdder acceptSocketErrorsCount = new LongAdder();
    private final LongAdder acceptIoErrorsCount = new LongAdder();
    private final LongAdder workerPoolRejectedCount = new LongAdder();
    private final LongAdder duplicateSocketCount = new LongAdder();
    private final LongAdder cleanedSocketsCount = new LongAdder();
    private final Object lifecycleLock = new Object();

    public HttpProxyServer(Set<Integer> ports, Set<Integer> transparentPorts, BlacklistLoader blacklist, HttpAnomalyDetector httpAnomalyDetector) {
        this.ports = Objects.requireNonNull(ports);
        if (this.ports.isEmpty()) {
            throw new IllegalArgumentException("Ports list cannot be empty");
        }
        this.transparentPorts = transparentPorts != null ? transparentPorts : Collections.emptySet();
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
                logger.warn("Прокси сервер уже запущен на портах {}", ports);
                return;
            }

            running = true;

            logger.info("Инициализация HTTP proxy на портах: {}", ports);

            for (int port : ports) {
                Thread thread = new NamedThreadFactory(
                        "HttpProxy-Server-Thread-" + port,
                        false
                ).newThread(() -> runServer(port));

                serverThreads.add(thread);
                thread.start();
            }
        }
        waitForSocketsReady();
    }

    public void stop() {
        synchronized (lifecycleLock) {
            if (!running) return;
            logger.info("Остановка HTTP proxy на портах: {}", ports);
            running = false;
            serverSockets.values().forEach(IoUtil::closeQuietly);
            serverSockets.clear();
            leasesBySocket.values().forEach(ConnectionLease::release);
            leasesBySocket.clear();
            activeClientSockets.forEach(IoUtil::closeQuietly);
            activeClientSockets.clear();
            socketActivity.clear();
        }

        joinServerThreads();
        logAggregatedStatistics();
        logger.info("Остановка HTTP proxy завершена на портах: {}", ports);
    }

    private void runServer(int port) {
        ServerSocket localServerSocket = null;
        try {
            localServerSocket = new ServerSocket(port);
            serverSockets.put(port, localServerSocket);
            logger.info("HTTP Proxy слушает порт {} {}", port, transparentPorts.contains(port) ? "(transparent)" : "(explicit)");
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
                handleAcceptedConnection(clientSocket, port);
            }
        } catch (IOException e) {
            if (running) {
                logger.error("Не удалось запустить HTTP Proxy на порту {}", port, e);
            } else {
                logger.info("HTTP Proxy остановлен на порту {}", port);
            }
        } finally {
            if (localServerSocket != null) {
                serverSockets.remove(port);
                closeQuietly(localServerSocket);
            }
            logger.info("HTTP Proxy server thread для порта {} завершён", port);
        }
    }

    private void handleAcceptedConnection(Socket clientSocket, int listenedPort) {
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

            SocketAddress originalDestination = null;
            if (transparentPorts.contains(listenedPort)) {
                originalDestination = OriginalDestination.getOriginalDestination(clientSocket);
                if (originalDestination == null) {
                    logger.warn("Cannot determine original destination for transparent proxy on port {}, client={}", listenedPort, clientIp);
                }
            }

            lease = ConnectionLease.fromReserved(
                    clientSocket,
                    clientIp,
                    connectionsByClient,
                    clientCounter,
                    connectionSlots,
                    originalDestination,
                    listenedPort
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

    private void joinServerThreads() {
        for (Thread thread : serverThreads) {
            if (thread == null || thread == Thread.currentThread()) continue;
            try {
                thread.join(5000L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void waitForSocketsReady() {
        long timeout = System.currentTimeMillis() + 5000L;

        while (System.currentTimeMillis() < timeout) {
            boolean allBound = true;
            for (int port : ports) {
                ServerSocket ss = serverSockets.get(port);
                if (ss == null || ss.isClosed() || !ss.isBound()) {
                    allBound = false;
                    break;
                }
            }
            if (allBound) return;

            try {
                Thread.sleep(50L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }

        logger.warn("HTTP Proxy не открыл все порты {} за 5 секунд", ports);
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
