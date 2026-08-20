package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class DnsServerHelper {

    private static final Logger logger = LoggerFactory.getLogger(DnsServerHelper.class);

    // ✅ П.6: бесполезный qname-кэш (ключ == значение) удалён полностью.
    //        Убраны: QNAME_CACHE_ENABLED, QNAME_CACHE_MAX_SIZE, QNAME_CACHE_TTL_MILLIS,
    //        qnameCache, qnameCacheLock, CachedQname, removeExpiredQnames.

    public static final class DnsRateLimiter {
        private final boolean enabled;
        private final int requestsPerSecond;
        private final int burst;
        private final long clientIdleNanos;
        private final ConcurrentHashMap<String, TokenBucket> buckets;
        // ✅ П.46 исключён: requestCounter оставлен — он триггерит быструю очистку
        private final AtomicLong requestCounter = new AtomicLong();
        private final Object cleanupLock = new Object();

        private volatile long nextCleanupNanos;

        private static final Logger logger =
                LoggerFactory.getLogger(DnsRateLimiter.class);

        private static final boolean RATE_LIMIT_LOGGING_ENABLED =
                getConfig().getBoolean("dns.logging.rate-limit-enabled");

        private static final int CLEANUP_EVERY_N_REQUESTS =
                getPositiveInt(
                        "dns.rate-limit.cleanup-every-n-requests",
                        1000
                );

        private static final int CLEANUP_PERCENT_TO_REMOVE =
                getPercent(
                        "dns.rate-limit.cleanup-percent-to-remove",
                        10
                );

        private DnsRateLimiter(
                boolean enabled,
                int requestsPerSecond,
                int burst,
                long clientIdleNanos,
                ConcurrentHashMap<String, TokenBucket> buckets
        ) {
            this.enabled = enabled;
            this.requestsPerSecond = requestsPerSecond;
            this.burst = burst;
            this.clientIdleNanos = clientIdleNanos;
            this.buckets = buckets;
        }

        public static DnsRateLimiter disabled() {
            return new DnsRateLimiter(
                    false,
                    0,
                    0,
                    0L,
                    new ConcurrentHashMap<>()
            );
        }

        public DnsRateLimiter(
                int requestsPerSecond,
                int burst,
                long clientIdleNanos
        ) {
            if (requestsPerSecond <= 0) {
                throw new IllegalArgumentException(
                        "requestsPerSecond must be > 0"
                );
            }
            if (burst <= 0) {
                throw new IllegalArgumentException("burst must be > 0");
            }
            if (clientIdleNanos <= 0) {
                throw new IllegalArgumentException(
                        "clientIdleNanos must be > 0"
                );
            }

            this.enabled = true;
            this.requestsPerSecond = requestsPerSecond;
            this.burst = burst;
            this.clientIdleNanos = clientIdleNanos;
            this.buckets = new ConcurrentHashMap<>();
        }

        public boolean tryAcquire(String clientIp) {
            if (!enabled) {
                return true;
            }

            if (clientIp == null || clientIp.isEmpty()) {
                return false;
            }

            long now = System.nanoTime();
            cleanupIfNeeded(now);

            TokenBucket bucket = buckets.computeIfAbsent(
                    clientIp,
                    ignored -> new TokenBucket(burst, now)
            );

            boolean acquired = bucket.tryAcquire(
                    now,
                    requestsPerSecond,
                    burst
            );

            if (!acquired) {
                if (RATE_LIMIT_LOGGING_ENABLED) {
                    logger.debug(
                            "Rate limit exceeded for client: {} (active={})",
                            clientIp,
                            buckets.size()
                    );
                }
                return false;
            }

            long count = requestCounter.incrementAndGet();

            if (count % CLEANUP_EVERY_N_REQUESTS == 0) {
                triggerFastCleanup(now);
            }

            return true;
        }

        private void cleanupIfNeeded(long now) {
            if (now < nextCleanupNanos) {
                return;
            }

            synchronized (cleanupLock) {
                if (now < nextCleanupNanos) {
                    return;
                }

                removeIdleBuckets(now);
                nextCleanupNanos = now
                        + Math.min(
                        clientIdleNanos,
                        TimeUnit.SECONDS.toNanos(60)
                );
            }
        }

        private void triggerFastCleanup(long now) {
            synchronized (cleanupLock) {
                int currentSize = buckets.size();

                if (currentSize < CLEANUP_EVERY_N_REQUESTS) {
                    return;
                }

                List<Map.Entry<String, TokenBucket>> idle =
                        new ArrayList<>();

                for (Map.Entry<String, TokenBucket> entry
                        : buckets.entrySet()) {
                    if (now - entry.getValue().getLastSeenNanos()
                            > clientIdleNanos) {
                        idle.add(entry);
                    }
                }

                idle.sort(
                        Comparator.comparingLong(
                                entry -> entry.getValue()
                                        .getLastSeenNanos()
                        )
                );

                int target = Math.max(
                        1,
                        (currentSize * CLEANUP_PERCENT_TO_REMOVE) / 100
                );

                int removed = 0;

                for (Map.Entry<String, TokenBucket> entry : idle) {
                    if (removed >= target) {
                        break;
                    }

                    if (buckets.remove(entry.getKey(), entry.getValue())) {
                        removed++;
                    }
                }

                if (removed > 0) {
                    logger.info(
                            "DNS RateLimiter: fast cleanup removed {} clients",
                            removed
                    );
                }
            }
        }

        private void removeIdleBuckets(long now) {
            for (Map.Entry<String, TokenBucket> entry
                    : buckets.entrySet()) {
                TokenBucket bucket = entry.getValue();

                if (now - bucket.getLastSeenNanos()
                        > clientIdleNanos) {
                    buckets.remove(entry.getKey(), bucket);
                }
            }
        }

        public int getActiveClients() {
            return buckets.size();
        }

        public void cleanupOldClients() {
            long now = System.nanoTime();

            synchronized (cleanupLock) {
                removeIdleBuckets(now);
            }
        }
    }

    private static final class TokenBucket {
        private double tokens;
        private long lastRefillNanos;
        private long lastSeenNanos;

        private TokenBucket(int burst, long now) {
            this.tokens = burst;
            this.lastRefillNanos = now;
            this.lastSeenNanos = now;
        }

        private synchronized boolean tryAcquire(
                long now,
                int requestsPerSecond,
                int burst
        ) {
            long elapsedNanos = now - lastRefillNanos;

            if (elapsedNanos > 0) {
                double newTokens =
                        (elapsedNanos / 1_000_000_000.0d)
                                * requestsPerSecond;

                tokens = Math.min(burst, tokens + newTokens);
                lastRefillNanos = now;
            }

            lastSeenNanos = now;

            if (tokens < 1.0d) {
                return false;
            }

            tokens -= 1.0d;
            return true;
        }

        private synchronized long getLastSeenNanos() {
            return lastSeenNanos;
        }
    }

    public static ExecutorService createWorkerPool(int numThreads) {
        if (numThreads <= 0) {
            throw new IllegalArgumentException(
                    "numThreads must be > 0"
            );
        }

        return new ThreadPoolExecutor(
                numThreads,
                numThreads,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(500),
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.AbortPolicy()
        );
    }


    public static void closeQuietly(DatagramSocket socket) {
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
    }

    public static void closeQuietly(ServerSocket socket) {
        if (socket == null || socket.isClosed()) {
            return;
        }

        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    public static void closeQuietly(Socket socket) {
        if (socket == null || socket.isClosed()) {
            return;
        }

        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    public static byte[] shortToBytes(int value) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException(
                    "Длина вне диапазона: " + value
            );
        }

        return new byte[]{
                (byte) ((value >> 8) & 0xFF),
                (byte) (value & 0xFF)
        };
    }

    // ✅ П.6: getQuestionName упрощён — бесполезный кэш удалён
    public static String getQuestionName(Message message) {
        if (message == null) return "unknown";
        Record question = message.getQuestion();
        if (question == null || question.getName() == null) return "unknown";
        return question.getName().toString();
    }

    public static String extractIpv4FromPtrQuery(String ptrName) {
        if (ptrName == null) {
            return null;
        }

        String name = ptrName.toLowerCase(Locale.ROOT);

        if (!name.endsWith(".in-addr.arpa.")) {
            return null;
        }

        String reversedIp = name.substring(
                0,
                name.length() - ".in-addr.arpa.".length()
        );

        String[] parts = reversedIp.split("\\.");

        if (parts.length != 4) {
            return null;
        }

        String ip = parts[3] + "." + parts[2] + "."
                + parts[1] + "." + parts[0];

        return isValidIpv4(ip) ? ip : null;
    }

    public static String extractIpv6FromPtrQuery(String ptrName) {
        if (ptrName == null) {
            return null;
        }

        String name = ptrName.toLowerCase(Locale.ROOT);

        if (!name.endsWith(".ip6.arpa.")) {
            return null;
        }

        String reversedNibbles = name.substring(
                0,
                name.length() - ".ip6.arpa.".length()
        );

        String[] nibbles = reversedNibbles.split("\\.");

        if (nibbles.length != 32) {
            return null;
        }

        StringBuilder hex = new StringBuilder(32);

        for (int i = nibbles.length - 1; i >= 0; i--) {
            String nibble = nibbles[i];

            if (nibble.length() != 1
                    || Character.digit(nibble.charAt(0), 16) < 0) {
                return null;
            }

            hex.append(nibble);
        }

        StringBuilder ipv6 = new StringBuilder(39);

        for (int i = 0; i < hex.length(); i += 4) {
            if (i > 0) {
                ipv6.append(':');
            }

            ipv6.append(hex, i, i + 4);
        }

        return ipv6.toString();
    }

    private static boolean isValidIpv4(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String[] parts = value.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }

            try {
                int number = Integer.parseInt(part);

                if (number < 0 || number > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

    public static Optional<String> checkQueryBlacklist(
            Message query,
            BlacklistSnapshot snapshot
    ) {
        if (query == null || snapshot == null) {
            return Optional.empty();
        }

        Record question = query.getQuestion();

        if (question == null || question.getName() == null) {
            return Optional.empty();
        }

        String qname = question.getName().toString();

        if (snapshot.checkDomain(qname).isBlocked()) {
            return Optional.of("запрещённый домен: " + qname);
        }

        String ipv4 = extractIpv4FromPtrQuery(qname);

        if (ipv4 != null && snapshot.checkIp(ipv4).isBlocked()) {
            return Optional.of("запрещённый IPv4: " + ipv4);
        }

        String ipv6 = extractIpv6FromPtrQuery(qname);

        if (ipv6 != null && snapshot.checkIp(ipv6).isBlocked()) {
            return Optional.of("запрещённый IPv6: " + ipv6);
        }

        return Optional.empty();
    }

    public static String checkResponseBlacklist(
            Message response,
            String requestedDomain,
            BlacklistLoader blacklist
    ) {
        if (response == null || blacklist == null) {
            return null;
        }

        BlacklistSnapshot snapshot = blacklist.snapshot();

        if (snapshot == null) {
            return null;
        }

        // ✅ П.28 исключён: уже один проход по секциям
        int[] sections = {
                Section.ANSWER,
                Section.AUTHORITY,
                Section.ADDITIONAL
        };

        for (int section : sections) {
            List<Record> records = response.getSection(section);

            if (records == null || records.isEmpty()) {
                continue;
            }

            for (Record record : records) {
                String reason = checkRecordBlacklist(
                        record,
                        section,
                        requestedDomain,
                        snapshot
                );

                if (reason != null) {
                    return reason;
                }
            }
        }

        return null;
    }

    private static String checkRecordBlacklist(
            Record record,
            int section,
            String requestedDomain,
            BlacklistSnapshot snapshot
    ) {
        if (record == null || snapshot == null) {
            return null;
        }

        Name ownerName = record.getName();

        if (ownerName != null
                && snapshot.checkDomain(ownerName.toString()).isBlocked()) {
            return "запрещённый owner domain "
                    + ownerName
                    + " в секции "
                    + Section.string(section)
                    + " для запроса "
                    + requestedDomain;
        }

        if (record instanceof ARecord aRecord) {
            String ip = aRecord.getAddress().getHostAddress();

            if (snapshot.checkIp(ip).isBlocked()) {
                return "запрещённый IPv4 "
                        + ip
                        + " в A-record, секция "
                        + Section.string(section);
            }

            return null;
        }

        if (record instanceof AAAARecord aaaaRecord) {
            String ip = aaaaRecord.getAddress().getHostAddress();

            if (snapshot.checkIp(ip).isBlocked()) {
                return "запрещённый IPv6 "
                        + ip
                        + " в AAAA-record, секция "
                        + Section.string(section);
            }

            return null;
        }

        Name targetName = extractTargetName(record);

        if (targetName != null
                && snapshot.checkDomain(targetName.toString()).isBlocked()) {
            return "запрещённый target domain "
                    + targetName
                    + " в "
                    + record.getClass().getSimpleName()
                    + ", секция "
                    + Section.string(section);
        }

        return null;
    }

    private static Name extractTargetName(Record record) {
        if (record instanceof CNAMERecord) {
            return ((CNAMERecord) record).getTarget();
        }

        if (record instanceof DNAMERecord) {
            return ((DNAMERecord) record).getTarget();
        }

        if (record instanceof PTRRecord) {
            return ((PTRRecord) record).getTarget();
        }

        if (record instanceof NSRecord) {
            return ((NSRecord) record).getTarget();
        }

        if (record instanceof MXRecord) {
            return ((MXRecord) record).getTarget();
        }

        if (record instanceof SRVRecord) {
            return ((SRVRecord) record).getTarget();
        }

        return null;
    }

    public static Message createRefusedResponse(Message query) {
        if (query == null) {
            throw new IllegalArgumentException("query must not be null");
        }

        Message response = new Message(query.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setRcode(Rcode.REFUSED);

        if (query.getQuestion() != null) {
            response.addRecord(query.getQuestion(), Section.QUESTION);
        }

        return response;
    }

    public static void sendRefusedResponse(
            DatagramSocket socket,
            DatagramPacket originalPacket,
            Message query
    ) throws IOException {
        if (socket == null || originalPacket == null || query == null) {
            throw new IllegalArgumentException(
                    "socket, originalPacket and query are required"
            );
        }

        Message response = createRefusedResponse(query);
        byte[] responseBytes = response.toWire();

        DatagramPacket reply = new DatagramPacket(
                responseBytes,
                responseBytes.length,
                originalPacket.getAddress(),
                originalPacket.getPort()
        );

        socket.send(reply);
    }

    public static void sendTcpRefusedResponse(
            OutputStream output,
            Message query
    ) throws IOException {
        if (output == null || query == null) {
            throw new IllegalArgumentException(
                    "output and query are required"
            );
        }

        Message refused = createRefusedResponse(query);
        byte[] refusedBytes = refused.toWire();

        output.write(shortToBytes(refusedBytes.length));
        output.write(refusedBytes);
        output.flush();
    }


    private static int getPositiveInt(String key, int defaultValue) {
        int value = getConfig().getInt(key);
        return value > 0 ? value : defaultValue;
    }

    private static int getPercent(String key, int defaultValue) {
        int value = getConfig().getInt(key);
        return value >= 0 && value <= 100 ? value : defaultValue;
    }
}