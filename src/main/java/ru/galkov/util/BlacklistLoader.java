package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.blacklist_source.BlacklistSource;
import ru.galkov.blacklist_source.RknBlacklistSource;

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

    private final List<BlacklistSource> sources;
    private final AtomicReference<BlacklistSnapshot> snapshot = new AtomicReference<>(BlacklistSnapshot.empty());
    private final Object reloadLock = new Object();
    private volatile boolean loaded;
    private volatile ScheduledExecutorService reloadExecutor;

    // ✅ П.4: Кэш для snapshot (избегаем повторного создания)
    private volatile BlacklistSnapshot cachedSnapshot;
    private volatile long cachedSnapshotTime;
    private static final long SNAPSHOT_CACHE_TTL_MILLIS = 5000; // 5 секунд

    public BlacklistLoader(List<BlacklistSource> sources) {
        if (sources == null) throw new IllegalArgumentException(LocaleUtil.getString("blacklist_sources_cannot_be_null"));
        this.sources = List.copyOf(sources);
    }

    public BlacklistSnapshot snapshot() {
        ensureLoaded();

        // ✅ П.4: Возвращаем кэш, если он ещё актуален
        long now = System.currentTimeMillis();
        if (cachedSnapshot != null && (now - cachedSnapshotTime) < SNAPSHOT_CACHE_TTL_MILLIS) {
            return cachedSnapshot;
        }

        // ✅ П.4: Обновляем кэш
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
            try {
                snapshot.set(buildSnapshot());
                // ✅ П.4: Сбрасываем кэш при reload
                cachedSnapshot = null;
                cachedSnapshotTime = 0;
                loaded = true;
                logger.info("{}", LogFields.kv("event", LocaleUtil.getString("blacklist_reload_ok")));
            } catch (Exception e) {
                logger.error("{} error={}", LogFields.kv("event", LocaleUtil.getString("blacklist_reload_error")), e.getMessage());
            }
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

    /**
     * ✅ П.24: Async I/O для blacklist sources — параллельная загрузка
     */
    private BlacklistSnapshot buildSnapshot() {
        DomainTrie domainTrie = new DomainTrie();
        Set<String> ips = new HashSet<>();
        Set<IpCidr> cidrs = new HashSet<>();
        int loadedSources = 0, totalRules = 0, invalidRules = 0, duplicateIps = 0;

        // ✅ П.24: Параллельная загрузка источников
        ExecutorService loaderExecutor = Executors.newFixedThreadPool(
                Math.min(sources.size(), Runtime.getRuntime().availableProcessors()),
                r -> {
                    Thread t = new Thread(r, "Blacklist-Loader-Thread");
                    t.setDaemon(true);
                    return t;
                }
        );

        try {
            List<CompletableFuture<SourceResult>> futures = sources.stream()
                    .map(source -> CompletableFuture.supplyAsync(() -> {
                        try {
                            long startedAt = System.currentTimeMillis();
                            logger.info(LocaleUtil.getString("blacklist_source_loading"), source);
                            List<BlacklistRule> rules = source.loadRules();
                            long duration = System.currentTimeMillis() - startedAt;
                            return new SourceResult(source, rules, duration, null);
                        } catch (Exception e) {
                            return new SourceResult(source, null, 0, e);
                        }
                    }, loaderExecutor))
                    .toList();

            // ✅ П.24: Сбор результатов
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

                int accepted = 0, invalid = 0;
                for (BlacklistRule rule : rules) {
                    if (rule == null || rule.value() == null) { invalid++; continue; }
                    String value = normalizeRule(rule.value());
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
                            domainTrie.addDomain(type == DomainTrie.MatchType.WILDCARD ? domain.substring(2) : domain, type);
                            accepted++;
                        }
                    }
                }
                loadedSources++;
                totalRules += accepted;
                invalidRules += invalid;
                logger.info(LocaleUtil.getString("blacklist_source_loaded"), result.source, rules.size(), accepted, invalid, result.duration);
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
        logger.info("{} {} {} {} {} {} {}",
                LogFields.kv("event", LocaleUtil.getString("blacklist_snapshot_built")),
                LogFields.kv("sourcesLoaded", loadedSources), LogFields.kv("rulesTotal", totalRules),
                LogFields.kv("ipsUnique", ips.size()), LogFields.kv("ipsCidr", cidrs.size()),
                LogFields.kv("ipsDuplicate", duplicateIps), LogFields.kv("rulesInvalid", invalidRules));
        return new BlacklistSnapshot(domainTrie, Set.copyOf(ips), Set.copyOf(cidrs));
    }

    /**
     * ✅ П.24: Вспомогательный класс для результата загрузки источника
     */
    private static class SourceResult {
        final BlacklistSource source;
        final List<BlacklistRule> rules;
        final long duration;
        final Exception error;

        SourceResult(BlacklistSource source, List<BlacklistRule> rules, long duration, Exception error) {
            this.source = source;
            this.rules = rules;
            this.duration = duration;
            this.error = error;
        }
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
            reloadExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "Blacklist-Reload-Thread");
                t.setDaemon(true);
                return t;
            });
            reloadExecutor.scheduleWithFixedDelay(this::reloadNow, interval, interval, TimeUnit.SECONDS);
            logger.info(LocaleUtil.getString("blacklist_reload_enabled"), interval);
        }
    }

    private static String normalizeRule(String value) {
        if (value == null) return null;
        String result = value.trim();
        if (result.isEmpty() || result.startsWith("#") || result.startsWith("!")) return null;
        int commentIndex = result.indexOf('#');
        if (commentIndex >= 0) result = result.substring(0, commentIndex).trim();
        return result.isEmpty() ? null : result;
    }

    private static boolean isIpLiteral(String value) {
        if (value == null || value.isEmpty()) return false;
        if (value.indexOf(':') >= 0) return true;
        // IPv4
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
        // Проверка диапазонов 0-255
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
        ScheduledExecutorService executor = reloadExecutor;
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