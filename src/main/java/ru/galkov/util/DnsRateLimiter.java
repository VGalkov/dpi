package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class DnsRateLimiter {

    private static final Logger logger =
            LoggerFactory.getLogger(DnsRateLimiter.class);

    private static final boolean RATE_LIMIT_LOGGING_ENABLED =
            getConfig().getBoolean("dns.logging.rate-limit-enabled");

    private static final int CLEANUP_EVERY_N_REQUESTS =
            getPositiveInt("dns.rate-limit.cleanup-every-n-requests", 1000);

    private static final int CLEANUP_PERCENT_TO_REMOVE =
            getPercent("dns.rate-limit.cleanup-percent-to-remove", 10);

    private final boolean enabled;
    private final int requestsPerSecond;
    private final int burst;
    private final long clientIdleNanos;
    private final ConcurrentHashMap<String, TokenBucket> buckets;

    private final AtomicLong requestCounter = new AtomicLong();

    private final AtomicLong rejectedRequestCounter = new AtomicLong();

    private final Object cleanupLock = new Object();

    private volatile long nextCleanupNanos;

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
        if (requestsPerSecond <= 0) throw new IllegalArgumentException(LocaleUtil.getString("dns_rate_limiter_requests_per_second_invalid"));
        if (burst <= 0) throw new IllegalArgumentException(LocaleUtil.getString("dns_rate_limiter_burst_invalid"));
        if (clientIdleNanos <= 0) throw new IllegalArgumentException(LocaleUtil.getString("dns_rate_limiter_client_idle_nanos_invalid"));

        this.enabled = true;
        this.requestsPerSecond = requestsPerSecond;
        this.burst = burst;
        this.clientIdleNanos = clientIdleNanos;
        this.buckets = new ConcurrentHashMap<>();
    }

    public boolean tryAcquire(String clientIp) {
        if (!enabled) return true;
        if (clientIp == null || clientIp.isEmpty()) return false;
        long now = System.nanoTime();
        cleanupIfNeeded(now);
        TokenBucket bucket = buckets.computeIfAbsent(clientIp, ignored -> new TokenBucket(burst, now));
        boolean acquired = bucket.tryAcquire(now, requestsPerSecond, burst);

        if (!acquired) {
            if (RATE_LIMIT_LOGGING_ENABLED) rejectedRequestCounter.incrementAndGet();
            return false;
        }
        long count = requestCounter.incrementAndGet();
        if (count % CLEANUP_EVERY_N_REQUESTS == 0)
            triggerFastCleanup(now);

        return true;
    }

    private void cleanupIfNeeded(long now) {
        if (now < nextCleanupNanos) return;
        synchronized (cleanupLock) {
            if (now < nextCleanupNanos) return;
            removeIdleBuckets(now);

            nextCleanupNanos = now + Math.min(clientIdleNanos, TimeUnit.SECONDS.toNanos(60));
        }
    }

    private void triggerFastCleanup(long now) {
        synchronized (cleanupLock) {
            int currentSize = buckets.size();
            if (currentSize < CLEANUP_EVERY_N_REQUESTS) return;
            List<Map.Entry<String, TokenBucket>> idle = new ArrayList<>();

            for (Map.Entry<String, TokenBucket> entry : buckets.entrySet())
                if (now - entry.getValue().getLastSeenNanos() > clientIdleNanos) idle.add(entry);

            idle.sort(Comparator.comparingLong(entry -> entry.getValue().getLastSeenNanos()));
            int target = Math.max(1, currentSize * CLEANUP_PERCENT_TO_REMOVE / 100);
            int removed = 0;

            for (Map.Entry<String, TokenBucket> entry : idle) {
                if (removed >= target) break;
                if (buckets.remove(entry.getKey(), entry.getValue())) removed++;
            }

            if (removed > 0) {
                logger.info(
                        LocaleUtil.getString("dns_rate_limiter_cleanup_removed"),
                        removed,
                        rejectedRequestCounter.getAndSet(0)
                );
            }
        }
    }

    private void removeIdleBuckets(long now) {
        for (Map.Entry<String, TokenBucket> entry : buckets.entrySet()) {
            TokenBucket bucket = entry.getValue();
            if (now - bucket.getLastSeenNanos() > clientIdleNanos) buckets.remove(entry.getKey(), bucket);
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

    private static int getPositiveInt(String key, int defaultValue) {
        int value = getConfig().getInt(key);
        return value > 0 ? value : defaultValue;
    }

    private static int getPercent(String key, int defaultValue) {
        int value = getConfig().getInt(key);
        return value >= 0 && value <= 100 ? value : defaultValue;
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
                double newTokens = elapsedNanos / 1_000_000_000.0d * requestsPerSecond;
                tokens = Math.min(burst, tokens + newTokens);
                lastRefillNanos = now;
            }

            lastSeenNanos = now;
            if (tokens < 1.0d) return false;
            tokens -= 1.0d;
            return true;
        }

        private synchronized long getLastSeenNanos() {
            return lastSeenNanos;
        }
    }
}