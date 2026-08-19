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
import java.lang.ref.WeakReference;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 *
 * ✅ П.12: Periodic cleanup кэшей для предотвращения memory leak
 * ✅ П.23: TTL для dnsCache для защиты от DNS rebinding
 */
public class DnsServer {
    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);

    // ✅ П.23: Кэш resolved DNS upstream с TTL
    private static final Map<String, CachedInetAddress> dnsCache = new ConcurrentHashMap<>();
    // ✅ П.23: TTL для dnsCache (5 минут) - перенесено из static в instance
    private final long dnsCacheTtlMillis;
    // ✅ П.4: Ограничение размера dnsCache - перенесено из static в instance
    private final int maxDnsCacheSize;

    // ✅ П.21: Кэш для getQuestionName() с TTL - перенесено из static в instance
    private final boolean qnameCacheEnabled;
    private final int qnameCacheMaxSize;
    private final long qnameCacheTtlMillis;
    private final Map<Integer, CachedQname> qnameCache;

    // ✅ П.4: Ограничение размера packet pool - перенесено из static в instance
    private final int maxPacketPoolSize;

    // ✅ П.21: ThreadLocal buffer для queryData (избегаем аллокаций) - перенесено из static в instance
    private final boolean queryDataBufferEnabled;
    private final int queryDataBufferSize;
    private final ThreadLocal<byte[]> queryDataBuffer;

    // ✅ П.8: ThreadLocal для DataInputStream в TCP (переиспользование) - перенесено из static в instance
    private final boolean tcpDataInputStreamPoolEnabled;
    private final ThreadLocal<DataInputStream> tcpDataInputStreamPool;

    // ✅ П.11: TCP socket timeout - перенесено из static в instance
    private final int tcpSocketTimeoutMillis;
    private final boolean tcpKeepAlive;
    private final boolean tcpNoDelay;

    // ✅ П.17: Логирование проблемных клиентов - перенесено из static в instance
    private final boolean rateLimitLoggingEnabled;

    // ✅ П.19: Защита от гонок - перенесено из static в instance
    private final int maxConcurrentRetries;

    // ✅ П.12: Интервал очистки кэшей - перенесено из static в instance
    private final int cacheCleanupIntervalSeconds;

    // ✅ П.2: Ограничение размера queriesByClient - перенесено из static в instance
    private final int maxQueriesByClient;

    // ✅ П.3: Ограничение размера activeUdpSockets - перенесено из static в instance
    private final int maxActiveUdpSocketsMultiplier;

    private final DnsAnomalyDetector dnsAnomalyDetector;
    private final ExecutorService workerPool;
    private final BlacklistLoader blacklist;
    private final Map<String, SimpleResolver> resolvers;
    private final DnsServerHelper.DnsRateLimiter rateLimiter;
    private final Object lifecycleLock = new Object();
    private final int maxPacketSize;
    private final int maxClients;
    private final int maxQueriesPerClient;
    private final int maxActiveSockets;
    private final int maxResponseSize;
    // ✅ П.18: Счётчик запросов на клиента
    private final Map<String, AtomicInteger> queriesByClient = new ConcurrentHashMap<>();

    // ✅ П.14: Активные UDP-сокеты
    private final Map<String, AtomicInteger> activeUdpSockets = new ConcurrentHashMap<>();

    // ✅ П.7: AtomicBoolean вместо volatile
    private final AtomicBoolean running = new AtomicBoolean();

    // ✅ П.21: Packet pool
    private final ArrayBlockingQueue<DatagramPacket> packetPool;

    private volatile DatagramSocket udpSocket;
    private volatile ServerSocket tcpListener;
    private volatile Thread tcpThread;

    // ✅ П.12: Scheduled executor для periodic cleanup
    private volatile ScheduledExecutorService cleanupExecutor;

    public DnsServer(BlacklistLoader blacklist, DnsAnomalyDetector dnsAnomalyDetector) {
        this.blacklist = Objects.requireNonNull(blacklist);
        this.resolvers = createResolvers();
        this.dnsAnomalyDetector = dnsAnomalyDetector;
        this.rateLimiter = createRateLimiter();
        this.workerPool = WorkerPool.get();

        // ✅ П.5 + П.21: Константы из application.properties (перенесено из static в instance)
        this.dnsCacheTtlMillis = getConfig().getInt("dns.dns-cache-ttl-minutes") * 60 * 1000L;
        this.maxDnsCacheSize = getConfig().getInt("dns.max-dns-cache-size");
        this.qnameCacheEnabled = getConfig().getBoolean("dns.qname-cache.enabled");
        this.qnameCacheMaxSize = getConfig().getInt("dns.qname-cache.max-size");
        this.qnameCacheTtlMillis = getConfig().getInt("dns.qname-cache.ttl-seconds") * 1000L;
        this.qnameCache = qnameCacheEnabled ? new ConcurrentHashMap<>(qnameCacheMaxSize) : null;
        this.maxPacketPoolSize = getConfig().getInt("dns.packet-pool.size");
        this.queryDataBufferEnabled = getConfig().getBoolean("dns.query-data-buffer.enabled");
        this.queryDataBufferSize = getConfig().getInt("dns.query-data-buffer.size");
        this.queryDataBuffer = queryDataBufferEnabled ? ThreadLocal.withInitial(() -> new byte[queryDataBufferSize]) : null;
        this.tcpDataInputStreamPoolEnabled = getConfig().getBoolean("dns.tcp-datainputstream-pool.enabled");
        this.tcpDataInputStreamPool = tcpDataInputStreamPoolEnabled ? ThreadLocal.withInitial(() -> null) : null;
        this.tcpSocketTimeoutMillis = getConfig().getInt("dns.tcp.socket-timeout-millis");
        this.tcpKeepAlive = getConfig().getBoolean("dns.tcp.keep-alive");
        this.tcpNoDelay = getConfig().getBoolean("dns.tcp.no-delay");
        this.rateLimitLoggingEnabled = getConfig().getBoolean("dns.logging.rate-limit-enabled");
        this.maxConcurrentRetries = getConfig().getInt("dns.concurrent.max-retries");
        this.cacheCleanupIntervalSeconds = getConfig().getInt("dns.cache-cleanup-interval-seconds");
        this.maxQueriesByClient = getConfig().getInt("dns.max-queries-by-client");
        this.maxActiveUdpSocketsMultiplier = getConfig().getInt("dns.max-active-udp-sockets-multiplier");

        this.maxPacketSize = getConfig().getInt("dns.max-packet-size");
        this.packetPool = new ArrayBlockingQueue<>(maxPacketPoolSize);
        for (int i = 0; i < maxPacketPoolSize; i++) {
            packetPool.offer(new DatagramPacket(new byte[maxPacketSize], maxPacketSize));
        }
        logger.info("Packet pool инициализирован: size={} ({} KB)", maxPacketPoolSize, (maxPacketPoolSize * maxPacketSize) / 1024);

        int rps = getConfig().getInt("dns.rate-limit.requests-per-second");
        int maxClientsMultiplier = getConfig().getInt("dns.max-clients-multiplier");
        int maxActiveSocketsMultiplier = getConfig().getInt("dns.max-active-sockets-multiplier");

        this.maxClients = rps * maxClientsMultiplier;
        this.maxQueriesPerClient = rps;
        this.maxActiveSockets = this.maxClients * maxActiveSocketsMultiplier;
        this.maxResponseSize = getConfig().getInt("dns.max-response-size");
        logger.info("DNS server config: maxPacketSize={}, poolSize={}, maxClients={}, maxQueriesPerClient={}, maxActiveSockets={}, TCP_TIMEOUT={}ms",
                maxPacketSize, maxPacketPoolSize, maxClients, maxQueriesPerClient, maxActiveSockets, tcpSocketTimeoutMillis);
    }

    public void run() {
        if (!running.compareAndSet(false, true)) {
            logger.warn("DNS server уже запущен");
            return;
        }

        // ✅ П.12: Запуск periodic cleanup
        startCacheCleanup();

        int port = getConfig().getInt("dns.local.port");
        logger.info("Запуск DNS форвардера на порту {}, maxPacketSize={}, maxClients={}, maxQueriesPerClient={}, maxActiveSockets={}, poolSize={}",
                port, maxPacketSize, maxClients, maxQueriesPerClient, maxActiveSockets, maxPacketPoolSize);
        try (DatagramSocket localUdpSocket = new DatagramSocket(port);
             ServerSocket localTcpListener = new ServerSocket(port)) {
            udpSocket = localUdpSocket;
            tcpListener = localTcpListener;
            startTcpAcceptor(localTcpListener);
            while (running.get()) {
                DatagramPacket request = packetPool.poll();
                if (request == null) {
                    request = new DatagramPacket(new byte[maxPacketSize], maxPacketSize);
                    logger.debug("Packet pool пуст, создан новый пакет");
                }

                try { localUdpSocket.receive(request); } catch (SocketException e) {
                    if (!running.get()) break;
                    throw e;
                }
                if (!running.get()) break;

                int length = request.getLength();
                if (length > maxPacketSize) {
                    logger.warn(LocaleUtil.getString("dns_server_max_packet_size"), length, maxPacketSize);
                    packetPool.offer(request);
                    continue;
                }

                InetAddress addr = request.getAddress();
                String clientIp = addr != null ? addr.getHostAddress() : "unknown";

                int maxActiveSocketsLimit = maxActiveSockets * maxActiveUdpSocketsMultiplier;
                if (activeUdpSockets.size() >= maxActiveSocketsLimit) {
                    logger.warn(LocaleUtil.getString("dns_server_active_udp_sockets_overflow"),
                            activeUdpSockets.size(), maxActiveSocketsLimit);
                    cleanupOldSockets();
                    packetPool.offer(request);
                    continue;
                }

                if (activeUdpSockets.size() >= maxActiveSockets) {
                    logger.warn(LocaleUtil.getString("dns_server_max_active_sockets"),
                            activeUdpSockets.size(), maxActiveSockets);
                    cleanupOldSockets();
                    packetPool.offer(request);
                    continue;
                }

                AtomicInteger clientQueries = getOrComputeAtomicInteger(queriesByClient, clientIp);
                if (clientQueries.incrementAndGet() > maxQueriesPerClient) {
                    clientQueries.decrementAndGet();
                    if (clientQueries.get() >= maxQueriesPerClient * 2) {
                        queriesByClient.remove(clientIp, clientQueries);
                    }
                    packetPool.offer(request);
                    continue;
                }

                if (rateLimiter.getActiveClients() >= maxClients) {
                    logger.warn(LocaleUtil.getString("dns_server_max_clients"), rateLimiter.getActiveClients(), maxClients);
                    rateLimiter.cleanupOldClients();
                    packetPool.offer(request);
                    continue;
                }

                AtomicInteger count = getOrComputeAtomicInteger(activeUdpSockets, clientIp);
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
                    packetPool.offer(request);
                }
            }
        } catch (IOException e) {
            if (running.get()) logger.error("Критическая ошибка запуска DNS-сервера", e);
        } finally {
            running.set(false);
            udpSocket = null;
            tcpListener = null;

            // ✅ П.12: Остановка cleanup executor
            stopCacheCleanup();

            logger.info("DNS server завершил работу");
        }
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        logger.info("Остановка DNS server начата");
        DnsServerHelper.closeQuietly(udpSocket);
        DnsServerHelper.closeQuietly(tcpListener);
        Thread currentTcpThread = tcpThread;
        if (currentTcpThread != null) currentTcpThread.interrupt();
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
     * ✅ П.23: Кэш resolved DNS upstream с TTL
     */
    private class CachedInetAddress {
        final InetAddress address;
        final long timestamp;

        CachedInetAddress(InetAddress address) {
            this.address = address;
            this.timestamp = System.currentTimeMillis();
        }

        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > dnsCacheTtlMillis;
        }

        long getAgeSeconds() {
            return (System.currentTimeMillis() - timestamp) / 1000;
        }
    }

    /**
     * ✅ П.5: WeakReference для защиты от OOM
     */
    private class CachedQname {
        final WeakReference<String> qnameRef;
        final long timestamp;

        CachedQname(String qname) {
            this.qnameRef = new WeakReference<>(qname);
            this.timestamp = System.currentTimeMillis();
        }

        String getQname() {
            return qnameRef.get();
        }

        boolean isExpired() {
            return (System.currentTimeMillis() - timestamp) > qnameCacheTtlMillis;
        }
    }

    /**
     * ✅ П.23: Кэш с TTL для защиты от DNS rebinding
     */
    private Map<String, SimpleResolver> createResolvers() {
        if (dnsCache.size() > maxDnsCacheSize) {
            logger.warn(LocaleUtil.getString("dns_server_dns_cache_overflow"), dnsCache.size(), maxDnsCacheSize);
            dnsCache.clear();
        }

        Map<String, SimpleResolver> result = new LinkedHashMap<>();
        int timeout = getConfig().getInt("dns.timeout");
        for (String dns : getConfig().getList("dns.list")) {
            try {
                CachedInetAddress cached = dnsCache.get(dns);
                InetAddress addr;

                if (cached != null && !cached.isExpired()) {
                    addr = cached.address;
                    logger.debug("Используем кэшированный DNS: {} -> {}", dns, addr);
                } else {
                    if (cached != null) {
                        logger.info(LocaleUtil.getString("dns_resolver_cache_expired"), dns, cached.getAgeSeconds());
                    }

                    addr = InetAddress.getByName(dns);
                    dnsCache.put(dns, new CachedInetAddress(addr));
                    logger.info(LocaleUtil.getString("dns_resolver_cache_refreshed"), dns, addr);
                }

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

    private Message processQuery(Message query, String clientIp, String qname) {
        BlacklistSnapshot snapshot = blacklist.snapshot();

        if (!rateLimiter.tryAcquire(clientIp)) {
            if (rateLimitLoggingEnabled) {
                logger.warn(LocaleUtil.getString("dns_server_rate_limit_exceeded"),
                        clientIp, rateLimiter.getActiveClients());
            }
            return null;
        }

        if (DnsServerHelper.checkQueryBlacklist(query, snapshot).isPresent()) {
            return null;
        }

        Message response = forwardToResolver(query);
        if (response == null) {
            return null;
        }

        if (DnsServerHelper.checkResponseBlacklist(response, qname, blacklist) != null) {
            return null;
        }

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
            int length = packet.getLength();
            if (length == 0 || length > maxPacketSize) {
                logger.warn(LocaleUtil.getString("dns_server_max_packet_size"), length, maxPacketSize);
                return;
            }

            byte[] queryData = queryDataBufferEnabled && queryDataBuffer != null && length <= queryDataBufferSize
                    ? queryDataBuffer.get()
                    : new byte[length];
            System.arraycopy(packet.getData(), packet.getOffset(), queryData, 0, length);

            Message query;
            try { query = new Message(queryData); } catch (Exception e) { return; }

            String qname = DnsServerHelper.getQuestionName(query);

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
            int remaining = clientQueries.decrementAndGet();
            if (remaining <= 0) queriesByClient.remove(clientIp, clientQueries);

            if (queriesByClient.size() > maxQueriesByClient) {
                logger.warn(LocaleUtil.getString("dns_server_queries_by_client_overflow"),
                        queriesByClient.size(), maxQueriesByClient);
                int removed = cleanupQueriesByClient();
                if (removed > 0) {
                    logger.info(LocaleUtil.getString("dns_server_memory_cleanup_executed"), removed);
                }
            }

            activeUdpSockets.computeIfPresent(clientIp, (k, v) -> {
                int newVal = v.decrementAndGet();
                return newVal <= 0 ? null : v;
            });
            packetPool.offer(packet);
        }
    }

    private void handleSingleTcpSession(Socket socket, String clientIp) {
        try {
            socket.setSoTimeout(tcpSocketTimeoutMillis);
            socket.setKeepAlive(tcpKeepAlive);
            socket.setTcpNoDelay(tcpNoDelay);
            logger.debug(LocaleUtil.getString("dns_server_tcp_socket_timeout"),
                    tcpSocketTimeoutMillis, tcpKeepAlive);

            AtomicInteger clientQueries = getOrComputeAtomicInteger(queriesByClient, clientIp);
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

                DataInputStream dataInput = tcpDataInputStreamPoolEnabled && tcpDataInputStreamPool != null
                        ? tcpDataInputStreamPool.get()
                        : null;

                if (dataInput == null) {
                    dataInput = new DataInputStream(input);
                    if (tcpDataInputStreamPoolEnabled && tcpDataInputStreamPool != null) {
                        tcpDataInputStreamPool.set(dataInput);
                    }
                } else {
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
            } catch (SocketTimeoutException e) {
                logger.debug("TCP [{}]: socket timeout ({}ms)", clientIp, tcpSocketTimeoutMillis);
            } catch (IOException e) {
                if (running.get() && !(e instanceof java.nio.channels.ClosedChannelException)) logger.debug("TCP [{}]: ошибка сессии", clientIp, e);
            } finally {
                int remaining = clientQueries.decrementAndGet();
                if (remaining <= 0) queriesByClient.remove(clientIp, clientQueries);
            }
        } catch (SocketException e) {
            logger.warn("TCP [{}]: ошибка настройки сокета", clientIp, e);
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
                    // ✅ П.9: Проверка размера ответа и установка флага TC при превышении
                    if (response.toWire().length > maxResponseSize) {
                        response.getHeader().setFlag(Flags.TC);
                        logger.debug("DNS response truncated: size={} > max={}",
                                response.toWire().length, maxResponseSize);
                    }

                    if (response.getHeader().getFlag(Flags.TC)) {
                        response = forwardToResolverTcp(query, resolver);
                    }
                    return response;
                }
            } catch (Exception e) {
                logger.debug("Ошибка upstream {}: {}", dns, e.getMessage());
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

    private AtomicInteger getOrComputeAtomicInteger(Map<String, AtomicInteger> map, String key) {
        AtomicInteger value = map.get(key);
        if (value == null) {
            value = map.computeIfAbsent(key, k -> new AtomicInteger());
        }
        return value;
    }

    private void cleanupOldSockets() {
        if (activeUdpSockets.size() >= maxActiveSockets) {
            activeUdpSockets.entrySet().stream()
                    .filter(e -> e.getValue().get() <= 0)
                    .limit(10)
                    .forEach(e -> activeUdpSockets.remove(e.getKey()));
        }

        int maxActiveSocketsLimit = maxActiveSockets * maxActiveUdpSocketsMultiplier;
        if (activeUdpSockets.size() > maxActiveSocketsLimit) {
            logger.warn(LocaleUtil.getString("dns_server_active_udp_sockets_overflow"),
                    activeUdpSockets.size(), maxActiveSocketsLimit);
            activeUdpSockets.clear();
        }
    }

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

    /**
     * ✅ П.12: Periodic cleanup кэшей для предотвращения memory leak
     */
    private void startCacheCleanup() {
        cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "DnsServer-Cache-Cleanup-Thread");
            t.setDaemon(true);
            return t;
        });

        cleanupExecutor.scheduleWithFixedDelay(() -> {
            try {
                cleanupCaches();
            } catch (Exception e) {
                logger.error("Error in cache cleanup", e);
            }
        }, cacheCleanupIntervalSeconds, cacheCleanupIntervalSeconds, TimeUnit.SECONDS);

        logger.info(LocaleUtil.getString("dns_cache_cleanup_scheduled"), cacheCleanupIntervalSeconds);
    }

    /**
     * ✅ П.12: Остановка cleanup executor
     */
    private void stopCacheCleanup() {
        if (cleanupExecutor != null) {
            cleanupExecutor.shutdown();
            try {
                if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                cleanupExecutor.shutdownNow();
            }
        }
    }

    /**
     * ✅ П.12: Очистка кэшей
     */
    private void cleanupCaches() {
        int removedQname = 0, removedQueries = 0, removedSockets = 0;

        if (qnameCache != null) {
            Iterator<Map.Entry<Integer, CachedQname>> iterator = qnameCache.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<Integer, CachedQname> entry = iterator.next();
                if (entry.getValue().isExpired()) {
                    iterator.remove();
                    removedQname++;
                }
            }
        }

        Iterator<Map.Entry<String, AtomicInteger>> queriesIterator = queriesByClient.entrySet().iterator();
        while (queriesIterator.hasNext()) {
            Map.Entry<String, AtomicInteger> entry = queriesIterator.next();
            if (entry.getValue().get() <= 0) {
                queriesIterator.remove();
                removedQueries++;
            }
        }

        Iterator<Map.Entry<String, AtomicInteger>> socketsIterator = activeUdpSockets.entrySet().iterator();
        while (socketsIterator.hasNext()) {
            Map.Entry<String, AtomicInteger> entry = socketsIterator.next();
            if (entry.getValue().get() <= 0) {
                socketsIterator.remove();
                removedSockets++;
            }
        }

        if (removedQname > 0 || removedQueries > 0 || removedSockets > 0) {
            logger.info(LocaleUtil.getString("dns_cache_cleanup_executed"), removedQname, removedQueries, removedSockets);
        }
    }
}
