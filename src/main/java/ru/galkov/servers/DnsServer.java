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
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class DnsServer {
    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);

    private final Map<String, CachedInetAddress> dnsCache = new ConcurrentHashMap<>();
    private final long dnsCacheTtlMillis;
    private final int maxDnsCacheSize;

    private final int maxPacketPoolSize;
    private final boolean queryDataBufferEnabled;
    private final int queryDataBufferSize;
    private final ThreadLocal<byte[]> queryDataBuffer;

    private final int tcpSocketTimeoutMillis;
    private final boolean tcpKeepAlive;
    private final boolean tcpNoDelay;
    private final boolean rateLimitLoggingEnabled;
    private final int maxConcurrentRetries;
    private final int cacheCleanupIntervalSeconds;
    private final int maxQueriesByClient;
    private final int maxTcpConnectionsPerClient;
    private final int maxTcpSessions;
    private final AtomicInteger activeTcpSessions = new AtomicInteger();
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
    private final Map<String, AtomicInteger> queriesByClient = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> activeUdpSockets = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> tcpConnectionsByClient = new ConcurrentHashMap<>();
    private final AtomicBoolean running = new AtomicBoolean();
    private final ArrayBlockingQueue<DatagramPacket> packetPool;
    private volatile DatagramSocket udpSocket;
    private volatile ServerSocket tcpListener;
    private volatile Thread tcpThread;
    private volatile ScheduledExecutorService cleanupExecutor;

    public DnsServer(BlacklistLoader blacklist, DnsAnomalyDetector dnsAnomalyDetector) {
        this.blacklist = Objects.requireNonNull(blacklist);
        this.dnsAnomalyDetector = dnsAnomalyDetector;
        this.rateLimiter = createRateLimiter();
        this.workerPool = WorkerPool.get();

        this.dnsCacheTtlMillis = getConfig().getInt("dns.dns-cache-ttl-minutes") * 60 * 1000L;
        this.maxDnsCacheSize = Math.max(1, getConfig().getInt("dns.max-dns-cache-size"));
        this.maxPacketPoolSize = getConfig().getInt("dns.packet-pool.size");
        this.queryDataBufferEnabled = getConfig().getBoolean("dns.query-data-buffer.enabled");
        this.queryDataBufferSize = getConfig().getInt("dns.query-data-buffer.size");
        this.queryDataBuffer = queryDataBufferEnabled ? ThreadLocal.withInitial(() -> new byte[queryDataBufferSize]) : null;
        this.tcpSocketTimeoutMillis = getConfig().getInt("dns.tcp.socket-timeout-millis");
        this.tcpKeepAlive = getConfig().getBoolean("dns.tcp.keep-alive");
        this.tcpNoDelay = getConfig().getBoolean("dns.tcp.no-delay");
        this.rateLimitLoggingEnabled = getConfig().getBoolean("dns.logging.rate-limit-enabled");
        this.maxConcurrentRetries = getConfig().getInt("dns.concurrent.max-retries");
        this.cacheCleanupIntervalSeconds = getConfig().getInt("dns.cache-cleanup-interval-seconds");
        this.maxQueriesByClient = getConfig().getInt("dns.max-queries-by-client");
        this.maxActiveUdpSocketsMultiplier = getConfig().getInt("dns.max-active-udp-sockets-multiplier");

        int tcpLimit = getConfig().getInt("dns.max-tcp-connections-per-client");
        this.maxTcpConnectionsPerClient = tcpLimit > 0 ? tcpLimit : 20;

        int tcpSessions = getConfig().getInt("dns.max-active-tcp-sessions");
        this.maxTcpSessions = tcpSessions > 0 ? tcpSessions : 100;

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

        this.resolvers = createResolvers();

        logger.info("DNS server config: maxPacketSize={}, poolSize={}, maxClients={}, maxQueriesPerClient={}, maxActiveSockets={}, maxTcpSessions={}, TCP_TIMEOUT={}ms",
                maxPacketSize, maxPacketPoolSize, maxClients, maxQueriesPerClient, maxActiveSockets, maxTcpSessions, tcpSocketTimeoutMillis);
    }

    public void run() {
        if (!running.compareAndSet(false, true)) {
            logger.warn("DNS server уже запущен");
            return;
        }

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
            stopCacheCleanup();
            logger.info("DNS server завершил работу");
        }
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) return;
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

                int active = activeTcpSessions.incrementAndGet();
                if (active > maxTcpSessions) {
                    activeTcpSessions.decrementAndGet();
                    logger.warn("DNS global TCP session limit exceeded: active={}, max={}",
                            activeTcpSessions.get(), maxTcpSessions);
                    DnsServerHelper.closeQuietly(socket);
                    continue;
                }

                AtomicInteger tcpCount = getOrComputeAtomicInteger(tcpConnectionsByClient, clientIp);
                if (tcpCount.incrementAndGet() > maxTcpConnectionsPerClient) {
                    tcpCount.decrementAndGet();
                    if (tcpCount.get() <= 0) tcpConnectionsByClient.remove(clientIp, tcpCount);
                    activeTcpSessions.decrementAndGet();
                    logger.warn("DNS TCP limit exceeded for client={} (max={})", clientIp, maxTcpConnectionsPerClient);
                    DnsServerHelper.closeQuietly(socket);
                    continue;
                }

                try { workerPool.execute(() -> handleSingleTcpSession(socket, clientIp, tcpCount)); }
                catch (RuntimeException e) {
                    logger.warn("DNS worker pool отклонил TCP-соединение от {}: {}", clientIp, e.getMessage());
                    int rem = tcpCount.decrementAndGet();
                    if (rem <= 0) tcpConnectionsByClient.remove(clientIp, tcpCount);
                    activeTcpSessions.decrementAndGet();
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

    private Map<String, SimpleResolver> createResolvers() {
        if (dnsCache.size() >= maxDnsCacheSize) cleanupDnsCacheBySize();
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
                    if (cached != null)
                        logger.info(LocaleUtil.getString("dns_resolver_cache_expired"), dns, cached.getAgeSeconds());

                    addr = InetAddress.getByName(dns);
                    if (dnsCache.size() >= maxDnsCacheSize) cleanupDnsCacheBySize();
                    dnsCache.put(dns, new CachedInetAddress(addr));
                    logger.info(LocaleUtil.getString("dns_resolver_cache_refreshed"), dns, addr);
                }

                if (addr == null) throw new IllegalArgumentException("Некорректный DNS upstream: " + dns);
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

    private void cleanupDnsCacheBySize() {
        int removed = 0;
        Iterator<Map.Entry<String, CachedInetAddress>> it = dnsCache.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().isExpired()) { it.remove(); removed++; }
        }
        while (dnsCache.size() > maxDnsCacheSize && !dnsCache.isEmpty()) {
            dnsCache.remove(dnsCache.keySet().iterator().next());
            removed++;
        }
        if (removed > 0) {
            logger.info(LocaleUtil.getString("dns_cache_size_eviction"), removed, dnsCache.size(), maxDnsCacheSize);
        }
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

        if (DnsServerHelper.checkQueryBlacklist(query, snapshot).isPresent()) return null;

        Message response = forwardToResolver(query);
        if (response == null) return null;

        if (DnsServerHelper.checkResponseBlacklist(response, qname, blacklist) != null) return null;


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

            byte[] wire = response.toWire();
            try {
                socket.send(new DatagramPacket(wire, wire.length, packet.getAddress(), packet.getPort()));
            } catch (IOException e) {
                if (running.get()) logger.error("UDP [{}]: не удалось отправить ответ для домена {}", clientIp, qname, e);
            }
        } catch (Throwable t) {
            logger.error("Unexpected error in processUdpRequest", t);
        } finally {
            int remaining = clientQueries.decrementAndGet();
            if (remaining <= 0) queriesByClient.remove(clientIp, clientQueries);

            activeUdpSockets.computeIfPresent(clientIp, (k, v) -> {
                int newVal = v.decrementAndGet();
                return newVal <= 0 ? null : v;
            });
            packetPool.offer(packet);
        }
    }

    private void handleSingleTcpSession(Socket socket, String clientIp, AtomicInteger tcpCount) {
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

                DataInputStream dataInput = new DataInputStream(input);

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
        } finally {
            if (tcpCount != null) {
                int rem = tcpCount.decrementAndGet();
                if (rem <= 0) tcpConnectionsByClient.remove(clientIp, tcpCount);
            }
            activeTcpSessions.decrementAndGet();
        }
    }

    private Message forwardToResolver(Message query) {
        if (query == null || query.getQuestion() == null) return null;
        for (Map.Entry<String, SimpleResolver> entry : resolvers.entrySet()) {
            SimpleResolver resolver = entry.getValue();
            try {
                Message response = resolver.send(query);
                if (response != null) {
                    byte[] responseBytes = response.toWire();
                    if (responseBytes.length > maxResponseSize) {
                        response.getHeader().setFlag(Flags.TC);
                        logger.debug("DNS response truncated: size={} > max={}", responseBytes.length, maxResponseSize);
                    }

                    if (response.getHeader().getFlag(Flags.TC)) {
                        response = forwardToResolverTcp(query, resolver);
                    }
                    return response;
                }
            } catch (Exception e) {
                logger.debug("Ошибка upstream: {}", e.getMessage());
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
        return map.computeIfAbsent(key, k -> new AtomicInteger());
    }

    private void cleanupOldSockets() {
        activeUdpSockets.entrySet().removeIf(e -> e.getValue().get() <= 0);
        int removed = 0;
        while (activeUdpSockets.size() > maxActiveSockets && !activeUdpSockets.isEmpty()) {
            activeUdpSockets.remove(activeUdpSockets.keySet().iterator().next());
            removed++;
        }
        if (removed > 0) {
            logger.info(LocaleUtil.getString("dns_active_sockets_size_eviction"), removed, activeUdpSockets.size(), maxActiveSockets);
        }
    }

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

    private void cleanupCaches() {
        int removedDns = 0, removedQueries = 0, removedSockets = 0;

        Iterator<Map.Entry<String, CachedInetAddress>> dnsIt = dnsCache.entrySet().iterator();
        while (dnsIt.hasNext()) {
            if (dnsIt.next().getValue().isExpired()) { dnsIt.remove(); removedDns++; }
        }
        while (dnsCache.size() > maxDnsCacheSize && !dnsCache.isEmpty()) {
            dnsCache.remove(dnsCache.keySet().iterator().next());
            removedDns++;
        }

        queriesByClient.entrySet().removeIf(e -> e.getValue().get() <= 0);
        while (queriesByClient.size() > maxQueriesByClient && !queriesByClient.isEmpty()) {
            queriesByClient.remove(queriesByClient.keySet().iterator().next());
            removedQueries++;
        }

        activeUdpSockets.entrySet().removeIf(e -> e.getValue().get() <= 0);
        while (activeUdpSockets.size() > maxActiveSockets && !activeUdpSockets.isEmpty()) {
            activeUdpSockets.remove(activeUdpSockets.keySet().iterator().next());
            removedSockets++;
        }

        tcpConnectionsByClient.entrySet().removeIf(e -> e.getValue().get() <= 0);

        if (removedDns > 0 || removedQueries > 0 || removedSockets > 0) {
            logger.info(LocaleUtil.getString("dns_cache_cleanup_executed"), removedDns + removedQueries + removedSockets);
        }
    }
}