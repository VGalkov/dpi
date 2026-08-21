package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.blacklist_source.BlacklistSource;
import ru.galkov.blacklist_source.RknBlacklistSource;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class BlacklistLoader implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(BlacklistLoader.class);

    private static final int MAX_RULES_PER_SOURCE = getConfig().getInt("blacklist.max-rules-per-source");
    private static final int MAX_RULES_RKN = getConfig().getInt("blacklist.max-rules-rkn");
    private static final int MAX_RULES_TOTAL = getConfig().getInt("blacklist.max-rules-total");
    private static final long MAX_MEMORY_MB = getConfig().getLong("blacklist.max-memory-mb");

    private static final int LOADER_THREAD_POOL_SIZE = getConfig().getInt("blacklist.loader-thread-pool-size");

    private static final long SNAPSHOT_CACHE_TTL_MILLIS =
            getConfig().getLong("blacklist.snapshot-cache-ttl-millis");

    private final List<BlacklistSource> sources;
    private final AtomicReference<BlacklistSnapshot> snapshot = new AtomicReference<>(BlacklistSnapshot.empty());
    private final Object reloadLock = new Object();
    private volatile boolean loaded;
    private volatile ScheduledExecutorService reloadExecutor;

    private volatile BlacklistSnapshot cachedSnapshot;
    private volatile long cachedSnapshotTime;

    private volatile CompletableFuture<BlacklistSnapshot> pendingSnapshot;

    public BlacklistLoader(List<BlacklistSource> sources) {
        if (sources == null) throw new IllegalArgumentException(LocaleUtil.getString("blacklist_sources_cannot_be_null"));
        this.sources = List.copyOf(sources);
    }

    public BlacklistSnapshot snapshot() {
        ensureLoaded();

        long now = System.currentTimeMillis();
        BlacklistSnapshot localSnapshot = cachedSnapshot;
        long localSnapshotTime = cachedSnapshotTime;

        if (localSnapshot != null && (now - localSnapshotTime) < SNAPSHOT_CACHE_TTL_MILLIS) {
            return localSnapshot;
        }

        BlacklistSnapshot freshSnapshot = snapshot.get();
        cachedSnapshot = freshSnapshot;
        cachedSnapshotTime = now;
        return freshSnapshot;
    }

    public void load() {
        ensureLoaded();
        startReloadScheduler();
    }

    public void reloadNow() {
        synchronized (reloadLock) {
            if (pendingSnapshot != null && !pendingSnapshot.isDone()) {
                logger.info("{}", LogFields.kv("event", "blacklist_reload_already_in_progress"));
                return;
            }

            pendingSnapshot = CompletableFuture.supplyAsync(this::buildSnapshot);

            pendingSnapshot.thenAccept(newSnapshot -> {
                try {
                    snapshot.set(newSnapshot);
                    cachedSnapshot = null;
                    cachedSnapshotTime = 0;
                    loaded = true;
                    logger.info("{}", LogFields.kv("event", LocaleUtil.getString("blacklist_reload_ok")));
                } catch (Exception e) {
                    logger.error("{} error={}", LogFields.kv("event", LocaleUtil.getString("blacklist_reload_error")), e.getMessage());
                }
            }).exceptionally(ex -> {
                logger.error("{} error={}", LogFields.kv("event", LocaleUtil.getString("blacklist_reload_error")), ex.getMessage());
                return null;
            });
        }
    }

    private void ensureLoaded() {
        if (loaded) return;
        synchronized (reloadLock) {
            if (loaded) return;
            try {
                snapshot.set(buildSnapshot());
                logger.info("{}", LogFields.kv("event", LocaleUtil.getString("blacklist_first_load_ok")));
            } catch (Exception e) {
                logger.error(LocaleUtil.getString("blacklist_critical_load_error"), e);
                snapshot.set(BlacklistSnapshot.empty());
            } finally {
                loaded = true;
            }
        }
    }

    private BlacklistSnapshot buildSnapshot() {
        DomainTrie domainTrie = new DomainTrie();
        Set<String> ips = new HashSet<>();
        Set<IpCidr> cidrs = new HashSet<>();
        int loadedSources = 0, totalRules = 0, invalidRules = 0, duplicateIps = 0, duplicateDomains = 0;

        ExecutorService loaderExecutor = Executors.newFixedThreadPool(
                LOADER_THREAD_POOL_SIZE,
                r -> {
                    Thread t = new Thread(r, "Blacklist-Loader-Thread");
                    t.setDaemon(true);
                    return t;
                }
        );

        logger.info(LocaleUtil.getString("blacklist_loader_thread_pool_size"), LOADER_THREAD_POOL_SIZE);

        try {
            List<CompletableFuture<SourceResult>> futures = sources.stream()
                    .map(source -> CompletableFuture.supplyAsync(() -> {
                        try {
                            long startedAt = System.currentTimeMillis();
                            logger.info(LocaleUtil.getString("blacklist_source_loading"), source);
                            List<BlacklistRule> rules = source.loadRules();
                            if (rules == null) {
                                logger.warn(LocaleUtil.getString("blacklist_source_null_rules"), source);
                                return new SourceResult(source, null, 0, new IllegalStateException("null rules"));
                            }
                            long duration = System.currentTimeMillis() - startedAt;
                            return new SourceResult(source, rules, duration, null);
                        } catch (Exception e) {
                            return new SourceResult(source, null, 0, e);
                        }
                    }, loaderExecutor))
                    .toList();

            for (CompletableFuture<SourceResult> future : futures) {
                SourceResult result = future.join();
                if (result.error != null) {
                    logger.error(LocaleUtil.getString("blacklist_source_load_error"), result.source, result.error);
                    continue;
                }

                List<BlacklistRule> rules = result.rules;
                if (rules == null) {
                    logger.warn(LocaleUtil.getString("blacklist_source_null"), result.source);
                    continue;
                }

                int originalSize = rules.size();
                int maxRulesForSource = (result.source instanceof RknBlacklistSource) ? MAX_RULES_RKN : MAX_RULES_PER_SOURCE;

                if (originalSize > maxRulesForSource) {
                    rules = rules.subList(0, maxRulesForSource);
                    logger.warn(
                            result.source instanceof RknBlacklistSource ?
                                    LocaleUtil.getString("blacklist_max_rules_rkn_exceeded") :
                                    LocaleUtil.getString("blacklist_max_rules_per_source_exceeded"),
                            result.source, originalSize, maxRulesForSource, maxRulesForSource
                    );

                    int truncatedPercent = (int)((originalSize - maxRulesForSource) * 100.0 / originalSize);
                    logger.warn(LocaleUtil.getString("blacklist_partial_load_warning"),
                            result.source, maxRulesForSource, originalSize, truncatedPercent);
                }

                int accepted = 0, invalid = 0;
                for (BlacklistRule rule : rules) {
                    if (rule == null || rule.value() == null) { invalid++; continue; }
                    String value = RuleNormalizer.normalizeRule(rule.value());
                    if (value == null) { invalid++; continue; }
                    if (value.indexOf('/') >= 0) {
                        try { cidrs.add(new IpCidr(value)); accepted++; } catch (Exception e) { invalid++; }
                    } else if (isIpLiteral(value)) {
                        String ip = HostNormalizer.normalizeIp(value);
                        if (ip == null) { invalid++; } else { if (!ips.add(ip)) duplicateIps++; accepted++; }
                    } else {
                        String domain = HostNormalizer.normalizeHost(value);
                        if (domain == null) { invalid++; }
                        else {
                            DomainTrie.MatchType type = domain.startsWith("*.") ? DomainTrie.MatchType.WILDCARD
                                    : (isSubtreeRule(result.source) ? DomainTrie.MatchType.SUBTREE : DomainTrie.MatchType.EXACT);

                            String domainToAdd = type == DomainTrie.MatchType.WILDCARD ? domain.substring(2) : domain;

                            if (!domainTrie.contains(domainToAdd)) {
                                domainTrie.addDomain(domainToAdd, type);
                                accepted++;
                            } else {
                                duplicateDomains++;
                            }
                        }
                    }

                    totalRules++;
                    if (totalRules > MAX_RULES_TOTAL) {
                        logger.warn(LocaleUtil.getString("blacklist_max_rules_total_exceeded"), totalRules, MAX_RULES_TOTAL);
                        break;
                    }
                }

                loadedSources++;
                invalidRules += invalid;

                logger.info(LocaleUtil.getString("blacklist_source_loaded"),
                        result.source, originalSize, accepted, invalid, result.duration);

                long usedMemoryMB = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024;
                logger.info(LocaleUtil.getString("blacklist_memory_check"), usedMemoryMB, MAX_MEMORY_MB);

                if (usedMemoryMB > MAX_MEMORY_MB) {
                    logger.error(LocaleUtil.getString("blacklist_max_memory_exceeded"), usedMemoryMB, MAX_MEMORY_MB);
                    throw new IllegalStateException(
                            "Превышен лимит памяти blacklist: " + usedMemoryMB + " MB > " + MAX_MEMORY_MB + " MB");
                }
            }
        } finally {
            loaderExecutor.shutdown();
            try {
                if (!loaderExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                    loaderExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                loaderExecutor.shutdownNow();
            }
        }

        if (!sources.isEmpty() && loadedSources == 0) throw new IllegalStateException(LocaleUtil.getString("blacklist_no_sources_loaded"));
        logger.info("{} {} {} {} {} {} {} {}",
                LogFields.kv("event", LocaleUtil.getString("blacklist_snapshot_built")),
                LogFields.kv("sourcesLoaded", loadedSources), LogFields.kv("rulesTotal", totalRules),
                LogFields.kv("ipsUnique", ips.size()), LogFields.kv("ipsCidr", cidrs.size()),
                LogFields.kv("ipsDuplicate", duplicateIps), LogFields.kv("domainsDuplicate", duplicateDomains),
                LogFields.kv("rulesInvalid", invalidRules));

        return new BlacklistSnapshot(domainTrie, Collections.unmodifiableSet(ips), Collections.unmodifiableSet(cidrs));
    }

    private record SourceResult(BlacklistSource source, List<BlacklistRule> rules, long duration, Exception error) {
    }

    private void startReloadScheduler() {
        if (!getConfig().getBoolean("blacklist.reload.enabled")) {
            logger.info(LocaleUtil.getString("blacklist_reload_disabled"));
            return;
        }
        int interval = getConfig().getInt("blacklist.reload.interval-seconds");
        if (interval <= 0) { logger.warn(LocaleUtil.getString("blacklist_reload_invalid_interval"), interval); return; }

        synchronized (reloadLock) {
            if (reloadExecutor != null && !reloadExecutor.isShutdown()) return;
            ScheduledExecutorService newExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "Blacklist-Reload-Thread");
                t.setDaemon(true);
                return t;
            });
            reloadExecutor = newExecutor;
            newExecutor.scheduleWithFixedDelay(this::reloadNow, interval, interval, TimeUnit.SECONDS);
            logger.info(LocaleUtil.getString("blacklist_reload_enabled"), interval);
        }
    }

    private static boolean isIpLiteral(String value) {
        if (value == null || value.isEmpty()) return false;
        if (value.indexOf(':') >= 0) return true;
        int len = value.length(), dots = 0, lastDot = -1;
        for (int i = 0; i < len; i++) {
            char c = value.charAt(i);
            if (c == '.') {
                if (++dots > 3 || i - lastDot - 1 > 3) return false;
                lastDot = i;
            } else if (c < '0' || c > '9') {
                return false;
            }
        }
        if (dots != 3) return false;
        String[] parts = value.split("\\.");
        for (String p : parts) {
            try {
                int n = Integer.parseInt(p);
                if (n < 0 || n > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    @Override
    public void close() {
        ScheduledExecutorService executor;
        synchronized (reloadLock) {
            executor = reloadExecutor;
            reloadExecutor = null;
        }
        if (executor == null) return;
        executor.shutdown();
        try { if (!executor.awaitTermination(5, TimeUnit.SECONDS)) executor.shutdownNow(); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); executor.shutdownNow(); }
        logger.info("{}", LogFields.kv("event", LocaleUtil.getString("blacklist_scheduler_stopped")));
    }

    private static boolean isSubtreeRule(BlacklistSource source) {
        return source instanceof RknBlacklistSource;
    }
}