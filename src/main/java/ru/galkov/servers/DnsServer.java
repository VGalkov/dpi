package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.SimpleResolver;
import ru.galkov.llm.DnsAnomalyDetector;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.BlacklistSnapshot;
import ru.galkov.util.DnsServerHelper;
import ru.galkov.util.LocaleUtil;

import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class DnsServer {
    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);

    // ✅ П.22: Кэш resolved DNS upstream
    private static final Map<String, InetAddress> dnsCache = new ConcurrentHashMap<>();
    // ✅ П.4: Ограничение размера dnsCache
    private static final int MAX_DNS_CACHE_SIZE = getConfig().getInt("dns.max-dns-cache-size");

    // ✅ П.21: Object pooling для DatagramPacket (настраиваемый размер)
    private final ArrayBlockingQueue<DatagramPacket> packetPool;
    private final int poolSize;

    // ✅ П.7: ThreadLocal buffer для queryData (избегаем аллокаций)
    private static final boolean QUERY_DATA_BUFFER_ENABLED = getConfig().getBoolean("dns.query-data-buffer.enabled");
    private static final int QUERY_DATA_BUFFER_SIZE = getConfig().getInt("dns.query-data-buffer.size");
    private static final ThreadLocal<byte[]> queryDataBuffer = QUERY_DATA_BUFFER_ENABLED
            ? ThreadLocal.withInitial(() -> {
        byte[] buffer = new byte[QUERY_DATA_BUFFER_SIZE];
        logger.info(LocaleUtil.getString("dns_server_threadlocal_buffer_created"), QUERY_DATA_BUFFER_SIZE);
        return buffer;
    })
            : null;

    // ✅ П.8: ThreadLocal для DataInputStream в TCP (переиспользование)
    private static final boolean TCP_DATAINPUTSTREAM_POOL_ENABLED = getConfig().getBoolean("dns.tcp-datainputstream-pool.enabled");
    private static final ThreadLocal<DataInputStream> tcpDataInputStreamPool = TCP_DATAINPUTSTREAM_POOL_ENABLED
            ? ThreadLocal.withInitial(() -> null)
            : null;

    private final DnsAnomalyDetector dnsAnomalyDetector;
    private final ExecutorService workerPool;
    private final BlacklistLoader blacklist;
    private final Map<String, SimpleResolver> resolvers;
    private final DnsServerHelper.DnsRateLimiter rateLimiter;
    private final Object lifecycleLock = new Object();
    private final int maxPacketSize;
    private final int maxClients;
    private final int maxQueriesPerClient;
    private final int maxActiveSockets;  // ✅ П.14: новый лимит

    // ✅ П.18: Счётчик запросов на клиента
    private final Map<String, AtomicInteger> queriesByClient = new ConcurrentHashMap<>();
    // ✅ П.2: Ограничение размера queriesByClient
    private static final int MAX_QUERIES_BY_CLIENT = getConfig().getInt("dns.max-queries-by-client");

    // ✅ П.14: Активные UDP-сокеты
    private final Map<String, AtomicInteger> activeUdpSockets = new ConcurrentHashMap<>();
    // ✅ П.3: Ограничение размера activeUdpSockets
    private static final int MAX_ACTIVE_UDP_SOCKETS_MULTIPLIER = getConfig().getInt("dns.max-active-udp-sockets-multiplier");

    // ✅ П.7: AtomicBoolean вместо volatile
    private final AtomicBoolean running = new AtomicBoolean();
    private volatile DatagramSocket udpSocket;
    private volatile ServerSocket tcpListener;
    private volatile Thread tcpThread;

    public DnsServer(BlacklistLoader blacklist, DnsAnomalyDetector dnsAnomalyDetector) {
        this.blacklist = Objects.requireNonNull(blacklist);
        this.resolvers = createResolvers();
        this.dnsAnomalyDetector = dnsAnomalyDetector;
        this.rateLimiter = createRateLimiter();
        this.workerPool = WorkerPool.get();  // ✅ П.26: общий worker pool

        // ✅ П.5 + П.21: Константы из application.properties
        this.maxPacketSize = getConfig().getInt("dns.max-packet-size");
        this.poolSize = getConfig().getInt("dns.packet-pool.size");
        this.packetPool = new ArrayBlockingQueue<>(poolSize);
        for (int i = 0; i < poolSize; i++) {
            packetPool.offer(new DatagramPacket(new byte[maxPacketSize], maxPacketSize));
        }
        logger.info("Packet pool инициализирован: size={} ({} KB)", poolSize, (poolSize * maxPacketSize) / 1024);

        int rps = getConfig().getInt("dns.rate-limit.requests-per-second");
        int maxClientsMultiplier = getConfig().getInt("dns.max-clients-multiplier");
        int maxActiveSocketsMultiplier = getConfig().getInt("dns.max-active-sockets-multiplier");

        this.maxClients = rps * maxClientsMultiplier;
        this.maxQueriesPerClient = rps;
        this.maxActiveSockets = this.maxClients * maxActiveSocketsMultiplier;

        logger.info("DNS server config: maxPacketSize={}, poolSize={}, maxClients={}, maxQueriesPerClient={}, maxActiveSockets={}",
                maxPacketSize, poolSize, maxClients, maxQueriesPerClient, maxActiveSockets);
    }

    public void run() {
        // ✅ П.8: compareAndSet вместо synchronized
        if (!running.compareAndSet(false, true)) {
            logger.warn("DNS server уже запущен");
            return;
        }
        int port = getConfig().getInt("dns.local.port");
        logger.info("Запуск DNS форвардера на порту {}, maxPacketSize={}, maxClients={}, maxQueriesPerClient={}, maxActiveSockets={}, poolSize={}",
                port, maxPacketSize, maxClients, maxQueriesPerClient, maxActiveSockets, poolSize);
        try (DatagramSocket localUdpSocket = new DatagramSocket(port);
             ServerSocket localTcpListener = new ServerSocket(port)) {
            udpSocket = localUdpSocket;
            tcpListener = localTcpListener;
            startTcpAcceptor(localTcpListener);
            while (running.get()) {
                // ✅ П.21 + П.6: Берём пакет из пула с авто-возвратом
                DatagramPacket request = packetPool.poll();
                if (request == null) {
                    // Fallback: создаём новый, если пул пуст
                    request = new DatagramPacket(new byte[maxPacketSize], maxPacketSize);
                    logger.debug("Packet pool пуст, создан новый пакет");  // ✅ П.4: trace → debug
                }

                try { localUdpSocket.receive(request); } catch (SocketException e) {
                    if (!running.get()) break;
                    throw e;
                }
                if (!running.get()) break;

                int length = request.getLength();
                if (length > maxPacketSize) {
                    logger.warn(LocaleUtil.getString("dns_server_max_packet_size"), length, maxPacketSize);
                    // ✅ П.21 + П.6: Возвращаем пакет в пул
                    packetPool.offer(request);
                    continue;
                }

                InetAddress addr = request.getAddress();
                String clientIp = addr != null ? addr.getHostAddress() : "unknown";

                // ✅ П.3 + П.14: Проверка на максимальное количество активных сокетов
                int maxActiveSocketsLimit = maxActiveSockets * MAX_ACTIVE_UDP_SOCKETS_MULTIPLIER;
                if (activeUdpSockets.size() >= maxActiveSocketsLimit) {
                    logger.warn(LocaleUtil.getString("dns_server_active_udp_sockets_overflow"),
                            activeUdpSockets.size(), maxActiveSocketsLimit);
                    cleanupOldSockets();  // ✅ Очистка старых сокетов
                    // ✅ П.21 + П.6: Возвращаем пакет в пул
                    packetPool.offer(request);
                    continue;
                }

                // ✅ П.14: Проверка на максимальное количество активных сокетов
                if (activeUdpSockets.size() >= maxActiveSockets) {
                    logger.warn(LocaleUtil.getString("dns_server_max_active_sockets"),
                            activeUdpSockets.size(), maxActiveSockets);
                    cleanupOldSockets();  // ✅ Очистка старых сокетов
                    // ✅ П.21 + П.6: Возвращаем пакет в пул
                    packetPool.offer(request);
                    continue;
                }

                // ✅ П.2 + П.4: Оптимизировано (get + computeIfAbsent)
                AtomicInteger clientQueries = queriesByClient.get(clientIp);
                if (clientQueries == null) {
                    clientQueries = queriesByClient.computeIfAbsent(clientIp, k -> new AtomicInteger());
                }
                if (clientQueries.incrementAndGet() > maxQueriesPerClient) {
                    clientQueries.decrementAndGet();
                    if (clientQueries.get() >= maxQueriesPerClient * 2) {
                        queriesByClient.remove(clientIp, clientQueries);
                    }
                    // ✅ П.21 + П.6: Возвращаем пакет в пул
                    packetPool.offer(request);
                    continue;
                }

                // Проверка на лимит клиентов
                if (rateLimiter.getActiveClients() >= maxClients) {
                    logger.warn(LocaleUtil.getString("dns_server_max_clients"), rateLimiter.getActiveClients(), maxClients);
                    rateLimiter.cleanupOldClients();
                    // ✅ П.21 + П.6: Возвращаем пакет в пул
                    packetPool.offer(request);
                    continue;
                }

                // ✅ П.2: Оптимизировано (get + computeIfAbsent)
                AtomicInteger count = activeUdpSockets.get(clientIp);
                if (count == null) {
                    count = activeUdpSockets.computeIfAbsent(clientIp, k -> new AtomicInteger());
                }
                count.incrementAndGet();

                try {
                    DatagramPacket finalRequest = request;
                    AtomicInteger finalClientQueries = clientQueries;
                    workerPool.execute(() -> processUdpRequest(localUdpSocket, finalRequest, clientIp, finalClientQueries));
                } catch (RuntimeException e) {
                    logger.warn("DNS worker pool отклонил UDP-запрос от {}: {}", clientIp, e.getMessage());
                    activeUdpSockets.computeIfPresent(clientIp, (k, v) -> {
                        int newVal = v.decrementAndGet();
                        return newVal <= 0 ? null : v;
                    });
                    // ✅ П.21 + П.6: Возвращаем пакет в пул
                    packetPool.offer(request);
                }
            }
        } catch (IOException e) {
            if (running.get()) logger.error("Критическая ошибка запуска DNS-сервера", e);
        } finally {
            running.set(false);
            udpSocket = null;
            tcpListener = null;
            // ✅ П.26: не закрываем общий worker pool
            logger.info("DNS server завершил работу");
        }
    }

    public void stop() {
        // ✅ П.8: compareAndSet вместо synchronized
        if (!running.compareAndSet(true, false)) {
            return;
        }
        logger.info("Остановка DNS server начата");
        DnsServerHelper.closeQuietly(udpSocket);
        DnsServerHelper.closeQuietly(tcpListener);
        Thread currentTcpThread = tcpThread;
        if (currentTcpThread != null) currentTcpThread.interrupt();
        // ✅ П.26: не закрываем общий worker pool
        logger.info("Остановка DNS server завершена");
    }

    private void startTcpAcceptor(ServerSocket serverSocket) {
        tcpThread = new Thread(() -> handleTcpConnections(serverSocket), "DnsServer-TCP-Acceptor");
        tcpThread.setDaemon(false);
        tcpThread.start();
    }

    private void handleTcpConnections(ServerSocket serverSocket) {
        while (running.get()) {
            try {
                Socket socket = serverSocket.accept();
                if (!running.get()) { DnsServerHelper.closeQuietly(socket); break; }
                InetAddress addr = socket.getInetAddress();
                String clientIp = addr != null ? addr.getHostAddress() : "unknown";
                try { workerPool.execute(() -> handleSingleTcpSession(socket, clientIp)); }
                catch (RuntimeException e) {
                    logger.warn("DNS worker pool отклонил TCP-соединение от {}: {}", clientIp, e.getMessage());
                    DnsServerHelper.closeQuietly(socket);
                }
            } catch (SocketException e) {
                if (running.get()) logger.warn("TCP accept error: {}", e.getMessage());
                break;
            } catch (IOException e) {
                if (running.get()) logger.debug("TCP accept error", e);
            }
        }
        logger.info("DNS TCP acceptor завершён");
    }

    private DnsServerHelper.DnsRateLimiter createRateLimiter() {
        boolean enabled = getConfig().getBoolean("dns.rate-limit.enabled");
        if (!enabled) {
            logger.info("DNS rate limit отключён");
            return DnsServerHelper.DnsRateLimiter.disabled();
        }
        int rps = getConfig().getInt("dns.rate-limit.requests-per-second");
        int burst = getConfig().getInt("dns.rate-limit.burst");
        int idle = getConfig().getInt("dns.rate-limit.client-idle-seconds");
        if (rps <= 0 || burst <= 0 || idle <= 0) throw new IllegalArgumentException("Rate limit params must be > 0");
        logger.info("DNS rate limit включён: rps={}, burst={}, idle={}", rps, burst, idle);
        return new DnsServerHelper.DnsRateLimiter(rps, burst, TimeUnit.SECONDS.toNanos(idle));
    }

    /**
     * ✅ П.22: Кэш resolved DNS upstream
     * ✅ П.4: Ограничение размера dnsCache
     */
    private Map<String, SimpleResolver> createResolvers() {
        // ✅ П.4: Проверка на переполнение dnsCache
        if (dnsCache.size() > MAX_DNS_CACHE_SIZE) {
            logger.warn(LocaleUtil.getString("dns_server_dns_cache_overflow"), dnsCache.size(), MAX_DNS_CACHE_SIZE);
            dnsCache.clear();
        }

        Map<String, SimpleResolver> result = new LinkedHashMap<>();
        int timeout = getConfig().getInt("dns.timeout");
        for (String dns : getConfig().getList("dns.list")) {
            try {
                // ✅ П.22: Кэшируем resolved адрес
                InetAddress addr = dnsCache.computeIfAbsent(dns, k -> {
                    try {
                        logger.debug("Resolving DNS upstream: {}", dns);
                        return InetAddress.getByName(k);
                    } catch (UnknownHostException e) {
                        logger.error("Некорректный DNS upstream: {}", dns, e);
                        return null;
                    }
                });

                if (addr == null) {
                    throw new IllegalArgumentException("Некорректный DNS upstream: " + dns);
                }

                SimpleResolver resolver = new SimpleResolver(addr);
                resolver.setTimeout(Duration.ofSeconds(timeout));
                result.put(dns, resolver);
            } catch (Exception e) {
                throw new IllegalArgumentException("Некорректный DNS upstream: " + dns, e);
            }
        }
        if (result.isEmpty()) throw new IllegalStateException("Список DNS upstream пуст");
        return Collections.unmodifiableMap(result);
    }

    // ✅ П.1: Новый общий метод для обработки запроса (DRY)
    private Message processQuery(Message query, String clientIp, String qname) {
        BlacklistSnapshot snapshot = blacklist.snapshot();

        // ✅ Проверка rate limit
        if (!rateLimiter.tryAcquire(clientIp)) {
            return null;
        }

        // ✅ Проверка blacklist (query)
        if (DnsServerHelper.checkQueryBlacklist(query, snapshot).isPresent()) {
            return null;
        }

        // ✅ Forward to resolver
        Message response = forwardToResolver(query);
        if (response == null) {
            return null;
        }

        // ✅ Проверка blacklist (response)
        if (DnsServerHelper.checkResponseBlacklist(response, qname, blacklist) != null) {
            return null;
        }

        // ✅ Запись в anomaly detector
        if (dnsAnomalyDetector != null && dnsAnomalyDetector.isEnabled()) {
            int queryType = query.getQuestion().getType();
            boolean isQuery = !query.getHeader().getFlag(Flags.QR);
            int opcode = query.getHeader().getOpcode();
            boolean isTruncated = query.getHeader().getFlag(Flags.TC);
            boolean recursionDesired = query.getHeader().getFlag(Flags.RD);
            int rcode = query.getHeader().getRcode();
            dnsAnomalyDetector.recordQuery(clientIp, qname, queryType, isQuery, opcode, isTruncated, recursionDesired, 0, rcode);
        }

        return response;
    }

    private void processUdpRequest(DatagramSocket socket, DatagramPacket packet, String clientIp, AtomicInteger clientQueries) {
        try {
            // ✅ П.6: Авто-возврат пакета в пул через try-finally
            int length = packet.getLength();
            if (length == 0 || length > maxPacketSize) {
                logger.warn(LocaleUtil.getString("dns_server_max_packet_size"), length, maxPacketSize);
                return;
            }

            // ✅ П.7: Используем ThreadLocal buffer (избегаем аллокаций)
            byte[] queryData = QUERY_DATA_BUFFER_ENABLED && queryDataBuffer != null && length <= QUERY_DATA_BUFFER_SIZE
                    ? queryDataBuffer.get()
                    : new byte[length];
            System.arraycopy(packet.getData(), packet.getOffset(), queryData, 0, length);

            Message query;
            try { query = new Message(queryData); } catch (Exception e) { return; }

            String qname = DnsServerHelper.getQuestionName(query);

            // ✅ П.1: Вызов общего метода processQuery()
            Message response = processQuery(query, clientIp, qname);
            if (response == null) {
                try { DnsServerHelper.sendRefusedResponse(socket, packet, query); } catch (IOException e) { /* ignore */ }
                return;
            }

            try {
                socket.send(DnsServerHelper.getFormattedReply(response, packet));
            } catch (IOException e) {
                if (running.get()) logger.error("UDP [{}]: не удалось отправить ответ для домена {}", clientIp, qname, e);
            }
        } catch (Throwable t) {
            logger.error("Unexpected error in processUdpRequest", t);
        } finally {
            // ✅ П.3 + П.18: Убрано if (clientQueries != null)
            int remaining = clientQueries.decrementAndGet();
            if (remaining <= 0) queriesByClient.remove(clientIp, clientQueries);

            // ✅ П.2: Проверка на переполнение queriesByClient
            if (queriesByClient.size() > MAX_QUERIES_BY_CLIENT) {
                logger.warn(LocaleUtil.getString("dns_server_queries_by_client_overflow"),
                        queriesByClient.size(), MAX_QUERIES_BY_CLIENT);
                int removed = cleanupQueriesByClient();
                if (removed > 0) {
                    logger.info(LocaleUtil.getString("dns_server_memory_cleanup_executed"), removed);
                }
            }

            // ✅ П.14: Уменьшение activeUdpSockets после обработки
            activeUdpSockets.computeIfPresent(clientIp, (k, v) -> {
                int newVal = v.decrementAndGet();
                return newVal <= 0 ? null : v;
            });
            // ✅ П.21 + П.6: Возвращаем пакет в пул (автоматически в finally)
            packetPool.offer(packet);
        }
    }

    private void handleSingleTcpSession(Socket socket, String clientIp) {
        try {
            AtomicInteger clientQueries = queriesByClient.computeIfAbsent(clientIp, k -> new AtomicInteger());
            // ✅ П.2: Оптимизировано (было 5 строк, стало 3)
            if (clientQueries.incrementAndGet() > maxQueriesPerClient) {
                clientQueries.decrementAndGet();
                if (clientQueries.get() >= maxQueriesPerClient * 2) {
                    queriesByClient.remove(clientIp, clientQueries);
                }
                DnsServerHelper.closeQuietly(socket);
                return;
            }

            try (Socket currentSocket = socket;
                 InputStream input = currentSocket.getInputStream();
                 OutputStream output = currentSocket.getOutputStream()) {

                // ✅ П.8: Используем ThreadLocal DataInputStream (переиспользование)
                DataInputStream dataInput = TCP_DATAINPUTSTREAM_POOL_ENABLED && tcpDataInputStreamPool != null
                        ? tcpDataInputStreamPool.get()
                        : null;

                if (dataInput == null) {
                    dataInput = new DataInputStream(input);
                    if (TCP_DATAINPUTSTREAM_POOL_ENABLED && tcpDataInputStreamPool != null) {
                        tcpDataInputStreamPool.set(dataInput);
                    }
                } else {
                    // Переиспользуем существующий (нужен reset)
                    logger.debug(LocaleUtil.getString("dns_server_tcp_datainputstream_reused"), clientIp);
                }

                while (running.get() && !currentSocket.isClosed()) {
                    int length;
                    try { length = dataInput.readUnsignedShort(); } catch (EOFException e) { break; }
                    if (length == 0 || length > maxPacketSize) {
                        logger.warn(LocaleUtil.getString("dns_server_max_packet_size"), length, maxPacketSize);
                        break;
                    }
                    byte[] requestData = new byte[length];
                    dataInput.readFully(requestData);
                    Message query;
                    try { query = new Message(requestData); } catch (Exception e) { continue; }

                    String qname = DnsServerHelper.getQuestionName(query);

                    // ✅ П.1: Вызов общего метода processQuery()
                    Message response = processQuery(query, clientIp, qname);
                    if (response == null) {
                        try { DnsServerHelper.sendTcpRefusedResponse(output, query); } catch (IOException e) { /* ignore */ }
                        continue;
                    }

                    byte[] responseBytes = response.toWire();
                    output.write(DnsServerHelper.shortToBytes(responseBytes.length));
                    output.write(responseBytes);
                    output.flush();
                }
            } catch (IOException e) {
                if (running.get() && !(e instanceof java.nio.channels.ClosedChannelException)) logger.debug("TCP [{}]: ошибка сессии", clientIp, e);
            } finally {
                // ✅ П.3 + П.18: Убрано if (remaining != null)
                int remaining = clientQueries.decrementAndGet();
                if (remaining <= 0) queriesByClient.remove(clientIp, clientQueries);
            }
        } catch (Throwable t) {
            logger.error("Unexpected error in handleSingleTcpSession", t);
        }
    }

    private Message forwardToResolver(Message query) {
        if (query == null || query.getQuestion() == null) return null;
        for (Map.Entry<String, SimpleResolver> entry : resolvers.entrySet()) {
            String dns = entry.getKey();
            SimpleResolver resolver = entry.getValue();
            try {
                Message response = resolver.send(query);
                if (response != null) {
                    if (response.getHeader().getFlag(Flags.TC)) {
                        response = forwardToResolverTcp(query, resolver);
                    }
                    return response;
                }
            } catch (Exception e) {
                // ✅ П.4: Убран logger.trace
                logger.debug("Ошибка upstream {}: {}", dns, e.getMessage());  // ✅ trace → debug
            }
        }
        return null;
    }

    private Message forwardToResolverTcp(Message query, SimpleResolver resolver) {
        try {
            resolver.setTCP(true);
            Message tcpResponse = resolver.send(query);
            resolver.setTCP(false);
            return tcpResponse;
        } catch (Exception e) {
            resolver.setTCP(false);
            return null;
        }
    }

    /**
     * ✅ П.9: Упрощённая очистка старых сокетов
     * ✅ П.3: Дополнительная защита от переполнения
     */
    private void cleanupOldSockets() {
        if (activeUdpSockets.size() >= maxActiveSockets) {
            activeUdpSockets.entrySet().stream()
                    .filter(e -> e.getValue().get() <= 0)
                    .limit(10)
                    .forEach(e -> activeUdpSockets.remove(e.getKey()));
        }

        // ✅ П.3: Аварийная очистка при критическом переполнении
        int maxActiveSocketsLimit = maxActiveSockets * MAX_ACTIVE_UDP_SOCKETS_MULTIPLIER;
        if (activeUdpSockets.size() > maxActiveSocketsLimit) {
            logger.warn(LocaleUtil.getString("dns_server_active_udp_sockets_overflow"),
                    activeUdpSockets.size(), maxActiveSocketsLimit);
            activeUdpSockets.clear();  // ← Аварийная очистка
        }
    }

    /**
     * ✅ П.2: Очистка queriesByClient при переполнении
     */
    private int cleanupQueriesByClient() {
        int removed = 0;
        Iterator<Map.Entry<String, AtomicInteger>> iterator = queriesByClient.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, AtomicInteger> entry = iterator.next();
            if (entry.getValue().get() <= 0) {
                iterator.remove();
                removed++;
            }
        }
        return removed;
    }
}