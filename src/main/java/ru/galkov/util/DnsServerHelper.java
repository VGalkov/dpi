package ru.galkov.util;

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

public final class DnsServerHelper {

    public static final class DnsRateLimiter {
        private final boolean enabled;
        private final int requestsPerSecond;
        private final int burst;
        private final long clientIdleNanos;
        private final ConcurrentHashMap<String, TokenBucket> buckets;
        private volatile long nextCleanupNanos;

        private DnsRateLimiter(boolean enabled, int requestsPerSecond, int burst, long clientIdleNanos, ConcurrentHashMap<String, TokenBucket> buckets) {
            this.enabled = enabled;
            this.requestsPerSecond = requestsPerSecond;
            this.burst = burst;
            this.clientIdleNanos = clientIdleNanos;
            this.buckets = buckets;
        }

        public static DnsRateLimiter disabled() {
            return new DnsRateLimiter(false, 0, 0, 0L, new ConcurrentHashMap<>());
        }

        public DnsRateLimiter(int requestsPerSecond, int burst, long clientIdleNanos) {
            this(true, requestsPerSecond, burst, clientIdleNanos, new ConcurrentHashMap<>());
        }

        public boolean tryAcquire(String clientIp) {
            if (!enabled) return true;
            if (clientIp == null || clientIp.isEmpty()) return true;
            long now = System.nanoTime();
            cleanupIfNeeded(now);
            TokenBucket bucket = buckets.computeIfAbsent(clientIp, ignored -> new TokenBucket(burst, now));
            return bucket.tryAcquire(now, requestsPerSecond, burst);
        }

        private void cleanupIfNeeded(long now) {
            long cleanupIntervalNanos = Math.min(clientIdleNanos, TimeUnit.SECONDS.toNanos(60));
            if (now < nextCleanupNanos) return;
            synchronized (this) {
                if (now < nextCleanupNanos) return;
                List<String> toRemove = new ArrayList<>();
                for (Map.Entry<String, TokenBucket> entry : buckets.entrySet()) {
                    if (now - entry.getValue().getLastSeenNanos() > clientIdleNanos) {
                        toRemove.add(entry.getKey());
                    }
                }
                for (String key : toRemove) {
                    buckets.remove(key);
                }
                nextCleanupNanos = now + cleanupIntervalNanos;
            }
        }

        public int getRequestsPerSecond() { return requestsPerSecond; }
        public int getBurst() { return burst; }

        public int getActiveClients() {
            return buckets.size();
        }

        public void clear() {
            buckets.clear();
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

        private synchronized boolean tryAcquire(long now, int requestsPerSecond, int burst) {
            long elapsedNanos = now - lastRefillNanos;
            if (elapsedNanos > 0) {
                double newTokens = (elapsedNanos / 1_000_000_000.0d) * requestsPerSecond;
                tokens = Math.min(burst, tokens + newTokens);
                lastRefillNanos = now;
            }
            lastSeenNanos = now;
            if (tokens < 1.0d) return false;
            tokens -= 1.0d;
            return true;
        }

        private synchronized long getLastSeenNanos() { return lastSeenNanos; }
    }

    public static ExecutorService createWorkerPool(int numThreads) {
        return new ThreadPoolExecutor(numThreads, numThreads, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(500), new ThreadPoolExecutor.CallerRunsPolicy());
    }

    public static void shutdownWorkerPool(ExecutorService pool) {
        pool.shutdown();
        try {
            if (!pool.awaitTermination(10, TimeUnit.SECONDS)) {
                pool.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            pool.shutdownNow();
        }
    }

    public static void closeQuietly(DatagramSocket socket) {
        if (socket != null && !socket.isClosed()) socket.close();
    }

    public static void closeQuietly(ServerSocket socket) {
        if (socket == null || socket.isClosed()) return;
        try { socket.close(); } catch (IOException ignored) {}
    }

    public static void closeQuietly(Socket socket) {
        if (socket == null || socket.isClosed()) return;
        try { socket.close(); } catch (IOException ignored) {}
    }

    public static byte[] shortToBytes(int value) {
        if (value < 0 || value > 0xFFFF) throw new IllegalArgumentException("Длина вне диапазона: " + value);
        return new byte[] { (byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF) };
    }

    public static String getQuestionName(Message message) {
        Record question = message.getQuestion();
        if (question == null || question.getName() == null) return "unknown";
        return question.getName().toString();
    }

    public static String extractIpv4FromPtrQuery(String ptrName) {
        if (ptrName == null) return null;
        String name = ptrName.toLowerCase(Locale.ROOT);
        if (!name.endsWith(".in-addr.arpa.")) return null;
        String reversedIp = name.substring(0, name.length() - ".in-addr.arpa.".length());
        String[] parts = reversedIp.split("\\.");
        if (parts.length != 4) return null;
        String ip = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];
        return isValidIpv4(ip) ? ip : null;
    }

    public static String extractIpv6FromPtrQuery(String ptrName) {
        if (ptrName == null) return null;
        String name = ptrName.toLowerCase(Locale.ROOT);
        if (!name.endsWith(".ip6.arpa.")) return null;
        String reversedNibbles = name.substring(0, name.length() - ".ip6.arpa.".length());
        String[] nibbles = reversedNibbles.split("\\.");
        if (nibbles.length != 32) return null;
        StringBuilder hex = new StringBuilder(32);
        for (int i = nibbles.length - 1; i >= 0; i--) {
            String nibble = nibbles[i];
            if (nibble.length() != 1 || Character.digit(nibble.charAt(0), 16) < 0) return null;
            hex.append(nibble);
        }
        StringBuilder ipv6 = new StringBuilder(39);
        for (int i = 0; i < hex.length(); i += 4) {
            if (i > 0) ipv6.append(':');
            ipv6.append(hex, i, i + 4);
        }
        return ipv6.toString();
    }

    private static boolean isValidIpv4(String value) {
        if (value == null || value.isEmpty()) return false;
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) return false;
            try {
                int n = Integer.parseInt(p);
                if (n < 0 || n > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    public static Optional<String> checkQueryBlacklist(Message query, BlacklistSnapshot snapshot) {
        if (query == null || snapshot == null) return Optional.empty();
        Record question = query.getQuestion();
        if (question == null || question.getName() == null) return Optional.empty();
        String qname = question.getName().toString();
        if (snapshot.checkDomain(qname).isBlocked()) return Optional.of("запрещённый домен: " + qname);
        String ipv4 = extractIpv4FromPtrQuery(qname);
        if (ipv4 != null && snapshot.checkIp(ipv4).isBlocked()) return Optional.of("запрещённый IPv4: " + ipv4);
        String ipv6 = extractIpv6FromPtrQuery(qname);
        if (ipv6 != null && snapshot.checkIp(ipv6).isBlocked()) return Optional.of("запрещённый IPv6: " + ipv6);
        return Optional.empty();
    }

    public static String checkResponseBlacklist(Message response, String requestedDomain, BlacklistLoader blacklist) {
        if (response == null || blacklist == null) return null;
        BlacklistSnapshot snapshot = blacklist.snapshot();
        if (snapshot == null) return null;
        int[] sections = { Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL };
        for (int section : sections) {
            List<Record> records = response.getSection(section);
            if (records == null || records.isEmpty()) continue;

            for (Record record : records) {
                String reason = checkRecordBlacklist(record, section, requestedDomain, snapshot);
                if (reason != null) return reason;
            }
        }
        return null;
    }

    private static String checkRecordBlacklist(Record record, int section, String requestedDomain, BlacklistSnapshot snapshot) {
        if (record == null || snapshot == null) return null;
        Name ownerName = record.getName();
        if (ownerName != null && snapshot.checkDomain(ownerName.toString()).isBlocked())
            return "запрещённый owner domain " + ownerName + " в секции " + Section.string(section) + " для запроса " + requestedDomain;

        if (record instanceof ARecord) {
            String ip = ((ARecord) record).getAddress().getHostAddress();
            if (snapshot.checkIp(ip).isBlocked())
                return "запрещённый IPv4 " + ip + " в A-record, секция " + Section.string(section);
            return null;
        }

        if (record instanceof AAAARecord) {
            String ip = ((AAAARecord) record).getAddress().getHostAddress();
            if (snapshot.checkIp(ip).isBlocked())
                return "запрещённый IPv6 " + ip + " в AAAA-record, секция " + Section.string(section);
            return null;
        }

        Name targetName = extractTargetName(record);
        if (targetName != null && snapshot.checkDomain(targetName.toString()).isBlocked())
            return "запрещённый target domain " + targetName + " в " + record.getClass().getSimpleName() + ", секция " + Section.string(section);

        return null;
    }

    private static Name extractTargetName(Record record) {
        if (record instanceof CNAMERecord) return ((CNAMERecord) record).getTarget();
        if (record instanceof DNAMERecord) return ((DNAMERecord) record).getTarget();
        if (record instanceof PTRRecord) return ((PTRRecord) record).getTarget();
        if (record instanceof NSRecord) return ((NSRecord) record).getTarget();
        if (record instanceof MXRecord) return ((MXRecord) record).getTarget();
        if (record instanceof SRVRecord) return ((SRVRecord) record).getTarget();
        return null;
    }

    public static Message createRefusedResponse(Message query) {
        Message response = query.clone();
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setRcode(Rcode.REFUSED);
        return response;
    }

    public static void sendRefusedResponse(DatagramSocket socket, DatagramPacket originalPacket, Message query) throws IOException {
        Message response = createRefusedResponse(query);
        byte[] responseBytes = response.toWire();
        DatagramPacket reply = new DatagramPacket(responseBytes, responseBytes.length, originalPacket.getAddress(), originalPacket.getPort());
        socket.send(reply);
    }

    public static void sendTcpRefusedResponse(OutputStream output, Message query) throws IOException {
        Message refused = createRefusedResponse(query);
        byte[] refusedBytes = refused.toWire();
        output.write(shortToBytes(refusedBytes.length));
        output.write(refusedBytes);
        output.flush();
    }

    public static DatagramPacket getFormattedReply(Message response, DatagramPacket requestPacket) {
        byte[] responseData = response.toWire();
        return new DatagramPacket(responseData, responseData.length, requestPacket.getAddress(), requestPacket.getPort());
    }
}