package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.blacklist_source.BlacklistSource;
import ru.galkov.blacklist_source.RknBlacklistSource;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import static ru.galkov.Main.getConfig;
import static ru.galkov.util.RuleNormalizer.normalizeRule;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class BlacklistLoader implements AutoCloseable {

    private static final Logger logger =
            LoggerFactory.getLogger(BlacklistLoader.class);

    private static final int MAX_RULES_PER_SOURCE =
            getConfig().getInt("blacklist.max-rules-per-source");

    private static final int MAX_RULES_RKN =
            getConfig().getInt("blacklist.max-rules-rkn");

    private static final int MAX_RULES_TOTAL =
            getConfig().getInt("blacklist.max-rules-total");

    private static final long MAX_MEMORY_MB =
            getConfig().getLong("blacklist.max-memory-mb");

    private static final int LOADER_THREAD_POOL_SIZE =
            getConfig().getInt("blacklist.loader-thread-pool-size");

    private static final long SNAPSHOT_CACHE_TTL_MILLIS =
            getConfig().getLong(
                    "blacklist.snapshot-cache-ttl-millis"
            );

    /*
     * Максимальное количество имён источников,
     * раскрываемых в WARN-логах.
     *
     * Счётчики при этом не ограничиваются.
     */
    private static final int MAX_LOG_DETAILS = 20;

    private final List<BlacklistSource> sources;

    private final AtomicReference<BlacklistSnapshot> snapshot =
            new AtomicReference<>(BlacklistSnapshot.empty());

    private final Object reloadLock = new Object();

    private volatile boolean loaded;
    private volatile ScheduledExecutorService reloadExecutor;

    private volatile BlacklistSnapshot cachedSnapshot;
    private volatile long cachedSnapshotTime;

    private volatile CompletableFuture<BlacklistSnapshot> pendingSnapshot;

    public BlacklistLoader(List<BlacklistSource> sources) {
        if (sources == null) {
            throw new IllegalArgumentException(
                    LocaleUtil.getString(
                            "blacklist_sources_cannot_be_null"
                    )
            );
        }

        this.sources = List.copyOf(sources);
    }

    public BlacklistSnapshot snapshot() {
        ensureLoaded();

        long now = System.currentTimeMillis();

        BlacklistSnapshot localSnapshot = cachedSnapshot;
        long localSnapshotTime = cachedSnapshotTime;

        if (localSnapshot != null
                && now - localSnapshotTime
                < SNAPSHOT_CACHE_TTL_MILLIS) {
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
            if (pendingSnapshot != null
                    && !pendingSnapshot.isDone()) {
                logger.info("Blacklist reload already in progress");
                return;
            }

            pendingSnapshot = CompletableFuture.supplyAsync(
                    this::buildSnapshot
            );

            pendingSnapshot
                    .thenAccept(newSnapshot -> {
                        try {
                            snapshot.set(newSnapshot);
                            cachedSnapshot = null;
                            cachedSnapshotTime = 0;
                            loaded = true;

                            logger.info(
                                    "Blacklist reload completed successfully"
                            );
                        } catch (Exception e) {
                            logger.error(
                                    "Blacklist reload error",
                                    e
                            );
                        }
                    })
                    .exceptionally(ex -> {
                        logger.error(
                                "Blacklist reload error",
                                ex
                        );
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
                logger.info("Blacklist first load completed successfully");
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
        Map<String, String> domainSources = new ConcurrentHashMap<>();

        int loadedSources = 0;
        int totalRules = 0;
        int invalidRules = 0;
        int duplicateIps = 0;
        int duplicateDomains = 0;

        LoadLogStats logStats = new LoadLogStats(sources.size());
        long buildStartedAt = System.currentTimeMillis();
        ExecutorService loaderExecutor =
                Executors.newFixedThreadPool(
                        LOADER_THREAD_POOL_SIZE,
                        r -> {
                            Thread thread = new Thread(r, "Blacklist-Loader-Thread");
                            thread.setDaemon(true);
                            return thread;
                        }
                );

        logger.info(LocaleUtil.getString("blacklist_loader_thread_pool_size"), LOADER_THREAD_POOL_SIZE);

        try {
            List<CompletableFuture<SourceResult>> futures =
                    sources.stream()
                            .map(source ->
                                    loadSourceAsync(
                                            source,
                                            loaderExecutor
                                    )
                            )
                            .toList();

            for (CompletableFuture<SourceResult> future : futures) {
                SourceResult result = future.join();

                if (result.error() != null) {
                    logStats.sourceLoadErrors++;
                    addLogDetail(logStats.failedSources, result.source());
                    continue;
                }

                List<BlacklistRule> rules = result.rules();

                if (rules == null) {
                    logStats.sourceLoadErrors++;
                    addLogDetail(logStats.failedSources, result.source());
                    continue;
                }

                logStats.sourceLoadTimeMillis += result.duration();
                logStats.maxSourceDurationMillis = Math.max(logStats.maxSourceDurationMillis, result.duration());

                int originalSize = rules.size();
                logStats.rulesRead += originalSize;

                int maxRulesForSource =
                        result.source() instanceof RknBlacklistSource
                                ? MAX_RULES_RKN : MAX_RULES_PER_SOURCE;

                if (originalSize > maxRulesForSource) {
                    rules = rules.subList(0, maxRulesForSource);
                    logStats.truncatedSources++;
                    addLogDetail(
                            logStats.truncatedSourceDetails,
                            result.source()
                                    + " ["
                                    + originalSize
                                    + " -> "
                                    + maxRulesForSource
                                    + "]"
                    );
                }

                int accepted = 0;
                int invalid = 0;

                for (BlacklistRule rule : rules) {
                    if (rule == null || rule.value() == null) {
                        invalid++;
                        continue;
                    }

                    String value = normalizeRule(rule.value());

                    if (value == null) {
                        invalid++;
                        continue;
                    }

                    if (value.indexOf('/') >= 0) {
                        try {
                            cidrs.add(new IpCidr(value));
                            accepted++;
                        } catch (Exception e) {
                            invalid++;
                        }
                    } else if (HostNormalizer.isIpLiteralFast(value)) {
                        String ip = HostNormalizer.normalizeIp(value);

                        if (ip == null) {
                            invalid++;
                        } else {
                            if (!ips.add(ip)) duplicateIps++;
                            accepted++;
                        }
                    } else {
                        String domain = HostNormalizer.normalizeHost(value);

                        if (domain == null) {
                            invalid++;
                        } else {
                            DomainTrie.MatchType type =
                                    domain.startsWith("*.")
                                            ? DomainTrie.MatchType.WILDCARD
                                            : isSubtreeRule(result.source())
                                            ? DomainTrie.MatchType.SUBTREE
                                            : DomainTrie.MatchType.EXACT;

                            String domainToAdd =
                                    type == DomainTrie.MatchType.WILDCARD
                                            ? domain.substring(2) : domain;

                            if (!domainTrie.contains(domainToAdd)) {
                                domainTrie.addDomain(domainToAdd, type);

                                String sourceName = result.source().toString();
                                domainSources.put(domainToAdd, sourceName);

                                accepted++;
                            } else {
                                duplicateDomains++;
                            }
                        }
                    }

                    totalRules++;

                    if (totalRules > MAX_RULES_TOTAL) {
                        logStats.totalLimitReached = true;
                        break;
                    }
                }

                loadedSources++;
                invalidRules += invalid;

                logStats.loadedSources++;
                logStats.rulesAccepted += accepted;
                logStats.invalidRules += invalid;

                if (logger.isDebugEnabled()) {
                    logStats.sourceResults.add(
                            new SourceLogStats(
                                    result.source().toString(),
                                    originalSize,
                                    accepted,
                                    invalid,
                                    result.duration()
                            )
                    );
                }

                long usedMemoryMB = usedMemoryMb();

                logStats.maxMemoryMb = Math.max(
                        logStats.maxMemoryMb,
                        usedMemoryMB
                );

                if (usedMemoryMB > MAX_MEMORY_MB) {
                    logger.error(
                            LocaleUtil.getString("blacklist_max_memory_exceeded"),
                            usedMemoryMB,
                            MAX_MEMORY_MB
                    );

                    throw new IllegalStateException(
                            "Превышен лимит памяти blacklist: " + usedMemoryMB + " MB > " + MAX_MEMORY_MB + " MB");
                }
            }
        } finally {
            shutdownLoaderExecutor(loaderExecutor);
        }

        if (!sources.isEmpty() && loadedSources == 0) {
            throw new IllegalStateException(
                    LocaleUtil.getString("blacklist_no_sources_loaded")
            );
        }
        logStats.buildDurationMillis = elapsedMillis(buildStartedAt);
        logSnapshotSummary(
                logStats,
                loadedSources,
                totalRules,
                ips.size(),
                cidrs.size(),
                duplicateIps,
                duplicateDomains,
                invalidRules
        );

        return new BlacklistSnapshot(
                domainTrie,
                Collections.unmodifiableSet(ips),
                Collections.unmodifiableSet(cidrs),
                domainSources
        );
    }

    private CompletableFuture<SourceResult> loadSourceAsync(
            BlacklistSource source,
            ExecutorService loaderExecutor
    ) {
        return CompletableFuture.supplyAsync(() -> {
            long startedAt = System.currentTimeMillis();

            try {
                List<BlacklistRule> rules = source.loadRules();

                if (rules == null) {
                    return new SourceResult(
                            source,
                            null,
                            elapsedMillis(startedAt),
                            new IllegalStateException(
                                    "null rules"
                            )
                    );
                }

                return new SourceResult(source, rules, elapsedMillis(startedAt), null);
            } catch (Exception e) {
                return new SourceResult(source, null, elapsedMillis(startedAt), e);
            }
        }, loaderExecutor);
    }

    private void logSnapshotSummary(
            LoadLogStats stats,
            int loadedSources,
            int totalRules,
            int uniqueIps,
            int uniqueCidrs,
            int duplicateIps,
            int duplicateDomains,
            int invalidRules
    ) {
        logger.debug(
                "Blacklist snapshot built: "
                        + "sourcesLoaded={}/{}, "
                        + "sourceLoadErrors={}, "
                        + "rulesRead={}, "
                        + "rulesTotal={}, "
                        + "rulesAccepted={}, "
                        + "rulesInvalid={}, "
                        + "ipsUnique={}, "
                        + "ipsCidr={}, "
                        + "ipsDuplicate={}, "
                        + "domainsDuplicate={}, "
                        + "truncatedSources={}, "
                        + "totalLimitReached={}, "
                        + "maxMemoryMb={}, "
                        + "totalSourceLoadTimeMs={}, "
                        + "maxSourceDurationMs={}, "
                        + "buildDurationMs={}",
                loadedSources,
                stats.sourcesTotal,
                stats.sourceLoadErrors,
                stats.rulesRead,
                totalRules,
                stats.rulesAccepted,
                invalidRules,
                uniqueIps,
                uniqueCidrs,
                duplicateIps,
                duplicateDomains,
                stats.truncatedSources,
                stats.totalLimitReached,
                stats.maxMemoryMb,
                stats.sourceLoadTimeMillis,
                stats.maxSourceDurationMillis,
                stats.buildDurationMillis
        );

        logSourceErrors(stats);
        logTruncationDetails(stats);
        logSourceDetails(stats);
    }

    private void logSourceErrors(LoadLogStats stats) {
        if (stats.failedSources.isEmpty()) return;
        logger.warn("Blacklist source errors: count={}, details={}", stats.sourceLoadErrors, stats.failedSources);
    }

    private void logTruncationDetails(LoadLogStats stats) {
        if (stats.truncatedSourceDetails.isEmpty()) return;
        logger.warn(
                "Blacklist source rule limits reached: "
                        + "count={}, details={}",
                stats.truncatedSources,
                stats.truncatedSourceDetails
        );
    }

    private void logSourceDetails(LoadLogStats stats) {
        if (!logger.isDebugEnabled() || stats.sourceResults.isEmpty()) return;
        logger.debug("Blacklist source statistics: {}", stats.sourceResults);
    }

    private static void addLogDetail(List<String> details, Object value) {
        if (details.size() < MAX_LOG_DETAILS) details.add(String.valueOf(value));

    }

    private static long elapsedMillis(long startedAt) {
        return System.currentTimeMillis() - startedAt;
    }

    private static long usedMemoryMb() {
        Runtime runtime = Runtime.getRuntime();
        return (runtime.totalMemory() - runtime.freeMemory()) / 1024 / 1024;
    }

    private static void shutdownLoaderExecutor(ExecutorService loaderExecutor) {
        loaderExecutor.shutdown();
        try {
            if (!loaderExecutor.awaitTermination(30, TimeUnit.SECONDS)) loaderExecutor.shutdownNow();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            loaderExecutor.shutdownNow();
        }
    }

    private record SourceResult(
            BlacklistSource source,
            List<BlacklistRule> rules,
            long duration,
            Exception error
    ) {
    }

    private static final class LoadLogStats {

        private final int sourcesTotal;
        private int loadedSources;
        private int sourceLoadErrors;
        private int rulesRead;
        private int rulesAccepted;
        private int invalidRules;
        private int truncatedSources;
        private boolean totalLimitReached;
        private long sourceLoadTimeMillis;
        private long maxSourceDurationMillis;
        private long maxMemoryMb;
        private long buildDurationMillis;
        private final List<String> failedSources = new ArrayList<>();
        private final List<String> truncatedSourceDetails = new ArrayList<>();
        private final List<SourceLogStats> sourceResults = new ArrayList<>();

        private LoadLogStats(int sourcesTotal) {
            this.sourcesTotal = sourcesTotal;
        }
    }

    private record SourceLogStats(
            String source,
            int rulesRead,
            int accepted,
            int invalid,
            long durationMillis
    ) {
        @Override
        public String toString() {
            return source
                    + "{read=" + rulesRead
                    + ", accepted=" + accepted
                    + ", invalid=" + invalid
                    + ", durationMs=" + durationMillis
                    + '}';
        }
    }

    private void startReloadScheduler() {
        if (!getConfig().getBoolean("blacklist.reload.enabled")) {
            logger.info(LocaleUtil.getString("blacklist_reload_disabled"));
            return;
        }

        int interval = getConfig().getInt("blacklist.reload.interval-seconds");

        if (interval <= 0) {
            logger.warn(LocaleUtil.getString("blacklist_reload_invalid_interval"), interval);
            return;
        }

        synchronized (reloadLock) {
            if (reloadExecutor != null && !reloadExecutor.isShutdown()) {return;}
            ScheduledExecutorService newExecutor =
                    Executors.newSingleThreadScheduledExecutor(r -> {
                        Thread thread = new Thread(
                                r,
                                "Blacklist-Reload-Thread"
                        );
                        thread.setDaemon(true);
                        return thread;
                    });

            reloadExecutor = newExecutor;
            newExecutor.scheduleWithFixedDelay(this::reloadNow, interval, interval, TimeUnit.SECONDS);
            logger.info(LocaleUtil.getString("blacklist_reload_enabled"), interval);
        }
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

        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) executor.shutdownNow();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }

        logger.info("Blacklist reload scheduler stopped");
    }

    private static boolean isSubtreeRule(BlacklistSource source) {
        return source instanceof RknBlacklistSource;
    }
}