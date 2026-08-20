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

    // ✅ п.11: отслеживаем последнюю активность сокета (для удаления только idle)
    private final ConcurrentMap<Socket, Long> socketActivity = new ConcurrentHashMap<>();
    private final long idleCleanupThresholdMillis;

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

        // ✅ п.11 (доп.): множитель maxActiveSockets из конфига вместо хардкода *2
        int multiplier = getConfig().getInt("proxy.max-active-sockets-multiplier");
        this.maxActiveSockets = maxConnections * (multiplier > 0 ? multiplier : 2);

        // ✅ п.11: порог "idle" для очистки (секунды)
        int idleSec = getConfig().getInt("proxy.idle-socket-timeout-seconds");
        this.idleCleanupThresholdMillis = (idleSec > 0 ? idleSec : 30) * 1000L;

        // ✅ п.40: валидация в конструкторе (уже была)
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
            // ✅ п.11: очистка карты активности при остановке
            socketActivity.clear();
        }
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
            logger.info("HTTP Proxy server thread завершён");
        }
    }

    /**
     * ✅ П.10: Ограничение activeClientSockets
     * ✅ П.55: Атомарная проверка/добавление (оставлено, т.к. выбрано)
     * ✅ П.57: Проверка на null
     * ✅ п.11: фиксация активности при принятии
     */
    private void handleAcceptedConnection(Socket clientSocket) {
        String clientIp = clientSocket.getInetAddress().getHostAddress();

        // ✅ П.55: атомарная проверка и добавление
        if (!activeClientSockets.add(clientSocket)) {
            logger.warn(LocaleUtil.getString("http_proxy_max_sockets_reached"), activeClientSockets.size(), maxActiveSockets);
            closeQuietly(clientSocket);
            cleanupOldSockets();
            return;
        }

        // ✅ п.11: фиксируем время принятия как "активность"
        socketActivity.put(clientSocket, System.currentTimeMillis());

        if (activeClientSockets.size() > maxActiveSockets) {
            activeClientSockets.remove(clientSocket);
            socketActivity.remove(clientSocket);
            logger.warn(LocaleUtil.getString("http_proxy_max_sockets_reached"), activeClientSockets.size(), maxActiveSockets);
            closeQuietly(clientSocket);
            cleanupOldSockets();
            return;
        }

        if (!connectionSlots.tryAcquire()) {
            activeClientSockets.remove(clientSocket);
            socketActivity.remove(clientSocket);
            logger.warn("PROXY_CONNECTION_REJECT client={} reason=MAX_CONNECTIONS", clientIp);
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
            logger.warn("PROXY_CONNECTION_REJECT client={} reason=MAX_CONNECTIONS_PER_CLIENT", clientIp);
            closeQuietly(clientSocket);
            return;
        }

        logger.debug("PROXY_CONNECTION_ACCEPT client={} activeForClient={}", clientIp, activeForClient);

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
            logger.error("Не удалось передать соединение в worker pool: client={}", clientIp, e);
        }
    }

    /**
     * ✅ П.10: Очистка старых сокетов при переполнении
     * ✅ П.20: Исправление итерации с удалением
     * ✅ П.54: Snapshot для итерации
     * ✅ п.11: закрываем ТОЛЬКО idle-сокеты (без активности дольше порога)
     */
    private void cleanupOldSockets() {
        int currentSize = activeClientSockets.size();
        if (currentSize < maxActiveSockets) {
            return;
        }

        int toRemoveCount = getConfig().getInt("proxy.cleanup-sockets-per-iteration");
        long now = System.currentTimeMillis();
        int removed = 0;

        // ✅ п.11: отбираем только idle сокеты
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
            int removedPercent = (removed * 100) / currentSize;
            logger.info(LocaleUtil.getString("http_proxy_socket_cleanup_triggered"),
                    removed, removedPercent, currentSize);
        }
    }

    /**
     * ✅ П.56: Дополнительная очистка connectionsByClient (упрощена)
     */
    private void releaseConnectionSlot(String clientIp, AtomicInteger clientConnections) {
        int remaining = clientConnections.decrementAndGet();
        if (remaining <= 0) {
            connectionsByClient.remove(clientIp, clientConnections);
        }
        connectionSlots.release();
        logger.debug("PROXY_CONNECTION_CLOSE client={} activeForClient={}", clientIp, Math.max(remaining, 0));
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
}