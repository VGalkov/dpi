package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.SimpleResolver;
import ru.galkov.llm.DnsAnomalyDetector;
import ru.galkov.util.*;

import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

import static ru.galkov.Main.getConfig;
import static ru.galkov.util.IoUtil.closeQuietly;

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
    private final int cacheCleanupIntervalSeconds;
    private final int maxTcpConnectionsPerClient;
    private final int maxTcpSessions;
    private final AtomicInteger activeTcpSessions = new AtomicInteger();
    private final int maxActiveUdpSocketsMultiplier;
    private final DnsAnomalyDetector dnsAnomalyDetector;
    private final BlacklistLoader blacklist;
    private final Map<String, SimpleResolver> resolvers;
    private final DnsRateLimiter rateLimiter;
    private final int maxPacketSize;
    private final int maxClients;
    private final int maxQueriesPerClient;
    private final int maxActiveSockets;
    private final int maxResponseSize;
    private final int port;
    private final ClientCounterMap queriesByClient = new ClientCounterMap();
    private final ClientCounterMap activeUdpSockets = new ClientCounterMap();
    private final ClientCounterMap tcpConnectionsByClient = new ClientCounterMap();
    private final AtomicBoolean running = new AtomicBoolean();
    private final ArrayBlockingQueue<DatagramPacket> packetPool;
    private volatile DatagramSocket udpSocket;
    private volatile ServerSocket tcpListener;
    private volatile Thread tcpThread;
    private volatile ScheduledExecutorService cleanupExecutor;
    private final AtomicInteger resolverCacheRefreshCount = new AtomicInteger();

    private final LongAdder packetPoolEmptyCount = new LongAdder();
    private final LongAdder maxPacketSizeExceededCount = new LongAdder();
    private final LongAdder activeUdpSocketsOverflowCount = new LongAdder();
    private final LongAdder maxQueriesByClientExceededCount = new LongAdder();
    private final LongAdder maxClientsExceededCount = new LongAdder();
    private final LongAdder rateLimitExceededCount = new LongAdder();
    private final LongAdder udpWorkerRejectedCount = new LongAdder();
    private final LongAdder tcpWorkerRejectedCount = new LongAdder();
    private final LongAdder tcpSessionLimitExceededCount = new LongAdder();
    private final LongAdder tcpClientLimitExceededCount = new LongAdder();
    private final LongAdder upstreamErrorCount = new LongAdder();
    private final LongAdder udpSendErrorCount = new LongAdder();
    private final LongAdder tcpSessionErrorCount = new LongAdder();
    private final LongAdder tcpSocketErrorCount = new LongAdder();

    public DnsServer(BlacklistLoader blacklist, DnsAnomalyDetector dnsAnomalyDetector) {
        this.blacklist = Objects.requireNonNull(blacklist);
        this.dnsAnomalyDetector = dnsAnomalyDetector;

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
        this.cacheCleanupIntervalSeconds = getConfig().getInt("dns.cache-cleanup-interval-seconds");
        this.maxActiveUdpSocketsMultiplier = getConfig().getInt("dns.max-active-udp-sockets-multiplier");

        int tcpLimit = getConfig().getInt("dns.max-tcp-connections-per-client");
        this.maxTcpConnectionsPerClient = tcpLimit > 0 ? tcpLimit : 20;

        int tcpSessions = getConfig().getInt("dns.max-active-tcp-sessions");
        this.maxTcpSessions = tcpSessions > 0 ? tcpSessions : 100;

        this.maxPacketSize = getConfig().getInt("dns.max-packet-size");
        this.port = getConfig().getInt("dns.local.port");
        this.packetPool = new ArrayBlockingQueue<>(maxPacketPoolSize);
        for (int i = 0; i < maxPacketPoolSize; i++) {
            packetPool.offer(new DatagramPacket(new byte[maxPacketSize], maxPacketSize));
        }

        int rps = getConfig().getInt("dns.rate-limit.requests-per-second");
        int maxClientsMultiplier = getConfig().getInt("dns.max-clients-multiplier");
        int maxActiveSocketsMultiplier = getConfig().getInt("dns.max-active-sockets-multiplier");

        this.maxClients = rps * maxClientsMultiplier;
        this.maxQueriesPerClient = rps;
        this.maxActiveSockets = this.maxClients * maxActiveSocketsMultiplier;
        this.maxResponseSize = getConfig().getInt("dns.max-response-size");

        this.rateLimiter = createRateLimiter();
        this.resolvers = createResolvers();
    }

    public void run() {
        if (!running.compareAndSet(false, true)) {
            logger.warn("DNS server уже запущен");
            return;
        }

        startCacheCleanup();

        try (DatagramSocket localUdpSocket = new DatagramSocket(port);
             ServerSocket localTcpListener = new ServerSocket(port)) {
            udpSocket = localUdpSocket;
            tcpListener = localTcpListener;
            startTcpAcceptor(localTcpListener);
            logStartupSummary();

            while (running.get()) {
                DatagramPacket request = packetPool.poll();
                if (request == null) {
                    request = new DatagramPacket(new byte[maxPacketSize], maxPacketSize);
                    packetPoolEmptyCount.increment();
                }

                request.setLength(maxPacketSize);

                try {
                    localUdpSocket.receive(request);
                } catch (SocketException e) {
                    packetPool.offer(request);
                    if (!running.get()) break;
                    throw e;
                }

                if (!running.get()) {
                    packetPool.offer(request);
                    break;
                }

                int length = request.getLength();
                if (length > maxPacketSize) {
                    maxPacketSizeExceededCount.increment();
                    packetPool.offer(request);
                    continue;
                }

                InetAddress addr = request.getAddress();
                String clientIp = addr != null ? addr.getHostAddress() : "unknown";

                int maxActiveSocketsLimit = maxActiveSockets * maxActiveUdpSocketsMultiplier;

                if (activeUdpSockets.size() >= maxActiveSocketsLimit) {
                    activeUdpSocketsOverflowCount.increment();
                    cleanupOldSockets();
                    packetPool.offer(request);
                    continue;
                }

                AtomicInteger clientQueries = queriesByClient.getOrCreate(clientIp);

                if (clientQueries.incrementAndGet() > maxQueriesPerClient) {
                    maxQueriesByClientExceededCount.increment();
                    queriesByClient.decrementAndRemoveIfZero(clientIp, clientQueries);
                    packetPool.offer(request);
                    continue;
                }

                if (rateLimiter.getActiveClients() >= maxClients) {
                    maxClientsExceededCount.increment();
                    rateLimiter.cleanupOldClients();
                    queriesByClient.decrementAndRemoveIfZero(clientIp, clientQueries);
                    packetPool.offer(request);
                    continue;
                }

                AtomicInteger activeSockets = activeUdpSockets.getOrCreate(clientIp);
                activeSockets.incrementAndGet();
                DatagramPacket finalRequest = request;

                WorkerPool.SubmitResult submitResult =
                        WorkerPool.submit(
                                () -> processUdpRequest(
                                        localUdpSocket,
                                        finalRequest,
                                        clientIp,
                                        clientQueries,
                                        activeSockets
                                )
                        );

                if (submitResult != WorkerPool.SubmitResult.ACCEPTED) {
                    udpWorkerRejectedCount.increment();
                    queriesByClient.decrementAndRemoveIfZero(clientIp, clientQueries);
                    activeUdpSockets.decrementAndRemoveIfZero(clientIp, activeSockets);

                    finalRequest.setLength(maxPacketSize);
                    packetPool.offer(finalRequest);
                }
            }
        } catch (IOException e) {
            if (running.get())
                logger.error("Критическая ошибка запуска DNS-сервера", e);

        } finally {
            running.set(false);
            udpSocket = null;
            tcpListener = null;
            stopCacheCleanup();
            logAggregatedRuntimeStatistics();
            logger.info("DNS server завершил работу");
        }
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) return;
        closeQuietly(udpSocket);
        closeQuietly(tcpListener);
        Thread currentTcpThread = tcpThread;

        if (currentTcpThread != null) currentTcpThread.interrupt();

    }

    private void startTcpAcceptor(ServerSocket serverSocket) {
        tcpThread =
                new NamedThreadFactory(
                        "DnsServer-TCP-Acceptor",
                        false
                ).newThread(() -> handleTcpConnections(serverSocket));

        tcpThread.start();
    }

    private void handleTcpConnections(
            ServerSocket serverSocket
    ) {
        while (running.get()) {
            try {
                Socket socket = serverSocket.accept();

                if (!running.get()) {
                    closeQuietly(socket);
                    break;
                }

                InetAddress addr = socket.getInetAddress();
                String clientIp = addr != null ? addr.getHostAddress() : "unknown";
                int active = activeTcpSessions.incrementAndGet();

                if (active > maxTcpSessions) {
                    activeTcpSessions.decrementAndGet();
                    tcpSessionLimitExceededCount.increment();
                    closeQuietly(socket);
                    continue;
                }

                AtomicInteger tcpCount = tcpConnectionsByClient.getOrCreate(clientIp);

                if (tcpCount.incrementAndGet() > maxTcpConnectionsPerClient) {
                    tcpConnectionsByClient.decrementAndRemoveIfZero(clientIp, tcpCount);
                    activeTcpSessions.decrementAndGet();
                    tcpClientLimitExceededCount.increment();
                    closeQuietly(socket);
                    continue;
                }

                WorkerPool.SubmitResult submitResult =
                        WorkerPool.submit(() -> handleSingleTcpSession(socket, clientIp, tcpCount));

                if (submitResult != WorkerPool.SubmitResult.ACCEPTED) {
                    tcpWorkerRejectedCount.increment();
                    tcpConnectionsByClient.decrementAndRemoveIfZero(clientIp, tcpCount);

                    activeTcpSessions.decrementAndGet();
                    closeQuietly(socket);
                }
            } catch (SocketException e) {
                if (running.get()) tcpSocketErrorCount.increment();
                break;
            } catch (IOException e) {
                if (running.get()) tcpSessionErrorCount.increment();
            }
        }
    }

    private DnsRateLimiter createRateLimiter() {
        boolean enabled = getConfig().getBoolean("dns.rate-limit.enabled");
        if (!enabled) {return DnsRateLimiter.disabled();}
        int rps = getConfig().getInt("dns.rate-limit.requests-per-second");
        int burst = getConfig().getInt("dns.rate-limit.burst");
        int idle = getConfig().getInt("dns.rate-limit.client-idle-seconds");
        if (rps <= 0 || burst <= 0 || idle <= 0) {
            throw new IllegalArgumentException("Rate limit params must be > 0");
        }

        return new DnsRateLimiter(rps, burst, TimeUnit.SECONDS.toNanos(idle));
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
                    if (cached != null) {
                        logger.debug(
                                LocaleUtil.getString("dns_resolver_cache_expired"),
                                dns,
                                cached.getAgeSeconds());
                    }

                    addr = InetAddress.getByName(dns);

                    if (dnsCache.size() >= maxDnsCacheSize) cleanupDnsCacheBySize();
                    dnsCache.put(dns, new CachedInetAddress(addr));
                    resolverCacheRefreshCount.incrementAndGet();
                    logger.debug(LocaleUtil.getString("dns_resolver_cache_refreshed"), dns, addr);
                }

                if (addr == null)
                    throw new IllegalArgumentException("Некорректный DNS upstream: " + dns);

                SimpleResolver resolver = new SimpleResolver(addr);
                resolver.setTimeout(Duration.ofSeconds(timeout));
                result.put(dns, resolver);
            } catch (Exception e) {
                throw new IllegalArgumentException("Некорректный DNS upstream: " + dns, e);
            }
        }

        if (result.isEmpty())
            throw new IllegalStateException("Список DNS upstream пуст");
        return Collections.unmodifiableMap(result);
    }

    private void cleanupDnsCacheBySize() {
        int removed = 0;

        Iterator<Map.Entry<String, CachedInetAddress>> it = dnsCache.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().isExpired()) {it.remove();removed++;}
        }

        while (dnsCache.size() > maxDnsCacheSize && !dnsCache.isEmpty()) {
            dnsCache.remove(dnsCache.keySet().iterator().next());
            removed++;
        }

        if (removed > 0) {
            logger.debug(
                    LocaleUtil.getString("dns_cache_size_eviction"), removed, dnsCache.size(), maxDnsCacheSize);
        }
    }

    private Message processQuery(
            Message query,
            String clientIp,
            String qname
    ) {
        BlacklistSnapshot snapshot = blacklist.snapshot();

        if (!rateLimiter.tryAcquire(clientIp)) {
            if (rateLimitLoggingEnabled) rateLimitExceededCount.increment();
            return null;
        }

        if (DnsServerHelper.checkQueryBlacklist(query, snapshot).isPresent())
            return null;

        Message response = forwardToResolver(query);
        if (response == null) return null;
        if (DnsServerHelper.checkResponseBlacklist(response, qname, blacklist) != null)
            return null;

        if (dnsAnomalyDetector != null && dnsAnomalyDetector.isEnabled()) {
            int queryType = query.getQuestion().getType();
            boolean isQuery = !query.getHeader().getFlag(Flags.QR);
            int opcode = query.getHeader().getOpcode();
            boolean isTruncated = query.getHeader().getFlag(Flags.TC);
            boolean recursionDesired = query.getHeader().getFlag(Flags.RD);
            int rcode = query.getHeader().getRcode();

            dnsAnomalyDetector.recordQuery(
                    clientIp,
                    qname,
                    queryType,
                    isQuery,
                    opcode,
                    isTruncated,
                    recursionDesired,
                    0,
                    rcode
            );
        }

        return response;
    }

    private void processUdpRequest(
            DatagramSocket socket,
            DatagramPacket packet,
            String clientIp,
            AtomicInteger clientQueries,
            AtomicInteger activeSockets
    ) {
        try {
            int length = packet.getLength();
            if (length == 0 || length > maxPacketSize) {
                maxPacketSizeExceededCount.increment();
                return;
            }

            byte[] queryData =
                    queryDataBufferEnabled
                            && queryDataBuffer != null
                            && length <= queryDataBufferSize
                            ? queryDataBuffer.get()
                            : new byte[length];

            System.arraycopy(packet.getData(), packet.getOffset(), queryData, 0, length);
            Message query;

            try {
                query = new Message(Arrays.copyOf(queryData, length));
            } catch (Exception e) {
                return;
            }

            String qname = DnsServerHelper.getQuestionName(query);
            Message response = processQuery(query, clientIp, qname);

            if (response == null) {
                try {
                    DnsServerHelper.sendRefusedResponse(socket, packet, query);
                } catch (IOException ignored) {
                    // Client may have disconnected.
                }

                return;
            }

            byte[] wire = response.toWire();
            try {
                socket.send(
                        new DatagramPacket(
                                wire,
                                wire.length, packet.getAddress(),
                                packet.getPort())
                );
            } catch (IOException e) {
                if (running.get()) udpSendErrorCount.increment();
            }
        } catch (Throwable t) {
            logger.error("Unexpected error in processUdpRequest", t);
        } finally {
            queriesByClient.decrementAndRemoveIfZero(clientIp, clientQueries);
            activeUdpSockets.decrementAndRemoveIfZero(clientIp, activeSockets);
            packet.setLength(maxPacketSize);
            packetPool.offer(packet);
        }
    }

    private void handleSingleTcpSession(
            Socket socket,
            String clientIp,
            AtomicInteger tcpCount
    ) {
        AtomicInteger clientQueries = null;

        try {
            socket.setSoTimeout(tcpSocketTimeoutMillis);
            socket.setKeepAlive(tcpKeepAlive);
            socket.setTcpNoDelay(tcpNoDelay);
            clientQueries = queriesByClient.getOrCreate(clientIp);

            if (clientQueries.incrementAndGet() > maxQueriesPerClient) {
                maxQueriesByClientExceededCount.increment();
                queriesByClient.decrementAndRemoveIfZero(clientIp, clientQueries);

                clientQueries = null;
                return;
            }

            try (
                    Socket currentSocket = socket;
                    InputStream input = currentSocket.getInputStream();
                    OutputStream output = currentSocket.getOutputStream()
            ) {
                DataInputStream dataInput = new DataInputStream(input);

                while (running.get() && !currentSocket.isClosed()) {
                    int length;

                    try {
                        length = dataInput.readUnsignedShort();
                    } catch (EOFException e) {
                        break;
                    }

                    if (length == 0 || length > maxPacketSize) {
                        maxPacketSizeExceededCount.increment();
                        break;
                    }

                    byte[] requestData = new byte[length];

                    dataInput.readFully(requestData);

                    Message query;
                    try {
                        query = new Message(requestData);
                    } catch (Exception e) {
                        continue;
                    }

                    String qname = DnsServerHelper.getQuestionName(query);
                    Message response = processQuery(query, clientIp, qname);

                    if (response == null) {
                        try {
                            DnsServerHelper.sendTcpRefusedResponse(output, query);
                        } catch (IOException ignored) {
                            // Client may have disconnected.
                        }

                        continue;
                    }

                    byte[] responseBytes = response.toWire();
                    if (responseBytes.length > 65535) break;
                    output.write(DnsServerHelper.shortToBytes(responseBytes.length));

                    output.write(responseBytes);

                    output.flush();
                }
            } catch (SocketTimeoutException e) {
                tcpSessionErrorCount.increment();
            } catch (IOException e) {
                if (running.get() && !(e instanceof java.nio.channels.ClosedChannelException))
                    tcpSessionErrorCount.increment();
            } finally {
                queriesByClient.decrementAndRemoveIfZero(clientIp, clientQueries);
                clientQueries = null;
            }
        } catch (SocketException e) {
            if (running.get()) tcpSocketErrorCount.increment();
        } catch (Throwable t) {
            logger.error("Unexpected error in handleSingleTcpSession", t);
        } finally {
            if (clientQueries != null)
                queriesByClient.decrementAndRemoveIfZero(clientIp, clientQueries);
            tcpConnectionsByClient.decrementAndRemoveIfZero(clientIp, tcpCount);
            activeTcpSessions.decrementAndGet();
        }
    }

    private Message forwardToResolver(Message query) {
        if (query == null || query.getQuestion() == null) return null;

        for (Map.Entry<String, SimpleResolver> entry : resolvers.entrySet()) {
            SimpleResolver resolver = entry.getValue();

            try {
                Message response = resolver.send(query);
                if (response == null) continue;
                byte[] responseBytes = response.toWire();
                if (responseBytes.length > maxResponseSize) {
                    response.getHeader().setFlag(Flags.TC);
                    logger.debug(
                            "DNS response truncated: size={} > max={}",
                            responseBytes.length,
                            maxResponseSize
                    );
                }

                if (response.getHeader().getFlag(Flags.TC))
                    response = forwardToResolverTcp(query, resolver);


                return response;
            } catch (Exception e) {
                upstreamErrorCount.increment();
            }
        }

        return null;
    }

    private Message forwardToResolverTcp(Message query, SimpleResolver resolver) {
        try {
            resolver.setTCP(true);
            return resolver.send(query);
        } catch (Exception e) {
            upstreamErrorCount.increment();
            return null;
        } finally {
            resolver.setTCP(false);
        }
    }

    private void cleanupOldSockets() {
        activeUdpSockets.removeZeroCounters();

    }

    private void startCacheCleanup() {
        cleanupExecutor =
                Executors.newSingleThreadScheduledExecutor(
                        new NamedThreadFactory("DnsServer-Cache-Cleanup-Thread", true)
                );

        cleanupExecutor.scheduleWithFixedDelay(
                () -> {
                    try {
                        cleanupCaches();
                    } catch (Exception e) {
                        logger.error("Error in cache cleanup", e);
                    }
                },
                cacheCleanupIntervalSeconds,
                cacheCleanupIntervalSeconds,
                TimeUnit.SECONDS
        );
    }

    private void stopCacheCleanup() {
        ScheduledExecutorService executor = cleanupExecutor;

        cleanupExecutor = null;
        if (executor == null) return;
        executor.shutdown();

        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS))
                executor.shutdownNow();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
    }

    private void cleanupCaches() {
        int removedDns = 0;
        Iterator<Map.Entry<String, CachedInetAddress>> dnsIt = dnsCache.entrySet().iterator();
        while (dnsIt.hasNext()) {
            if (dnsIt.next().getValue().isExpired()) {
                dnsIt.remove();
                removedDns++;
            }
        }

        while (dnsCache.size() > maxDnsCacheSize && !dnsCache.isEmpty()) {
            dnsCache.remove(dnsCache.keySet().iterator().next());
            removedDns++;
        }

        queriesByClient.removeZeroCounters();
        activeUdpSockets.removeZeroCounters();
        tcpConnectionsByClient.removeZeroCounters();
        if (removedDns > 0)
            logger.debug("DNS cache cleanup completed: removed={}", removedDns);

    }

    private void logStartupSummary() {
        long packetPoolMemoryKb =
                (long) maxPacketPoolSize
                        * maxPacketSize
                        / 1024;

        logger.info(
                "DNS server started: port={}, "
                        + "maxPacketSize={}, "
                        + "packetPoolSize={}, "
                        + "packetPoolMemory={} KB, "
                        + "maxClients={}, "
                        + "maxQueriesPerClient={}, "
                        + "maxActiveSockets={}, "
                        + "maxTcpSessions={}, "
                        + "tcpTimeout={}ms, "
                        + "resolverCacheRefreshes={}",
                port,
                maxPacketSize,
                maxPacketPoolSize,
                packetPoolMemoryKb,
                maxClients,
                maxQueriesPerClient,
                maxActiveSockets,
                maxTcpSessions,
                tcpSocketTimeoutMillis,
                resolverCacheRefreshCount.get()
        );
    }

    private void logAggregatedRuntimeStatistics() {
        long packetPoolEmpty =
                packetPoolEmptyCount.sum();

        long maxPacketSizeExceeded =
                maxPacketSizeExceededCount.sum();

        long activeUdpSocketsOverflow =
                activeUdpSocketsOverflowCount.sum();

        long maxQueriesByClientExceeded =
                maxQueriesByClientExceededCount.sum();

        long maxClientsExceeded =
                maxClientsExceededCount.sum();

        long rateLimitExceeded =
                rateLimitExceededCount.sum();

        long udpWorkerRejected =
                udpWorkerRejectedCount.sum();

        long tcpWorkerRejected =
                tcpWorkerRejectedCount.sum();

        long tcpSessionLimitExceeded =
                tcpSessionLimitExceededCount.sum();

        long tcpClientLimitExceeded =
                tcpClientLimitExceededCount.sum();

        long upstreamErrors =
                upstreamErrorCount.sum();

        long udpSendErrors =
                udpSendErrorCount.sum();

        long tcpSessionErrors =
                tcpSessionErrorCount.sum();

        long tcpSocketErrors =
                tcpSocketErrorCount.sum();

        if (
                packetPoolEmpty == 0
                        && maxPacketSizeExceeded == 0
                        && activeUdpSocketsOverflow == 0
                        && maxQueriesByClientExceeded == 0
                        && maxClientsExceeded == 0
                        && rateLimitExceeded == 0
                        && udpWorkerRejected == 0
                        && tcpWorkerRejected == 0
                        && tcpSessionLimitExceeded == 0
                        && tcpClientLimitExceeded == 0
                        && upstreamErrors == 0
                        && udpSendErrors == 0
                        && tcpSessionErrors == 0
                        && tcpSocketErrors == 0
        ) {
            return;
        }

        logger.debug(
                "DNS server aggregated statistics: "
                        + "packetPoolEmpty={}, "
                        + "maxPacketSizeExceeded={}, "
                        + "activeUdpSocketsOverflow={}, "
                        + "maxQueriesByClientExceeded={}, "
                        + "maxClientsExceeded={}, "
                        + "rateLimitExceeded={}, "
                        + "udpWorkerRejected={}, "
                        + "tcpWorkerRejected={}, "
                        + "tcpSessionLimitExceeded={}, "
                        + "tcpClientLimitExceeded={}, "
                        + "upstreamErrors={}, "
                        + "udpSendErrors={}, "
                        + "tcpSessionErrors={}, "
                        + "tcpSocketErrors={}",
                packetPoolEmpty,
                maxPacketSizeExceeded,
                activeUdpSocketsOverflow,
                maxQueriesByClientExceeded,
                maxClientsExceeded,
                rateLimitExceeded,
                udpWorkerRejected,
                tcpWorkerRejected,
                tcpSessionLimitExceeded,
                tcpClientLimitExceeded,
                upstreamErrors,
                udpSendErrors,
                tcpSessionErrors,
                tcpSocketErrors
        );
    }
}