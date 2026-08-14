package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.blacklist_source.BlacklistSource;
import ru.galkov.blacklist_source.RknBlacklistSource;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class BlacklistLoader implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(BlacklistLoader.class);

    private final List<BlacklistSource> sources;
    private final AtomicReference<BlacklistSnapshot> snapshot =
            new AtomicReference<BlacklistSnapshot>(BlacklistSnapshot.empty());

    private final Object reloadLock = new Object();

    private volatile boolean loaded;
    private volatile ScheduledExecutorService reloadExecutor;

    public BlacklistLoader(List<BlacklistSource> sources) {
        if (sources == null)
            throw new IllegalArgumentException("Список источников blacklist не может быть null");
        this.sources = List.copyOf(sources);
    }

    public BlacklistSnapshot snapshot() {
        ensureLoaded();
        return snapshot.get();
    }

    public boolean isBlockedIp(String ip) {
        String normalizedIp = HostNormalizer.normalizeIp(ip);
        return normalizedIp != null && snapshot().containsIp(normalizedIp);
    }

    public boolean isBlockedDomain(String domain) {
        String normalizedDomain = HostNormalizer.normalizeHost(domain);
        return normalizedDomain != null && snapshot().matchesDomain(normalizedDomain);
    }

    /**
     * Выполняет первую синхронную загрузку и запускает планировщик, если это включено в application.properties.
     */
    public void load() {
        ensureLoaded();
        startReloadScheduler();
    }

    /**
     * Загружает источники немедленно.
     * В отличие от первой загрузки не очищает активный blacklist при ошибке: прежний snapshot остаётся рабочим.
     */
    public void reloadNow() {
        synchronized (reloadLock) {
            try {
                BlacklistSnapshot newSnapshot = buildSnapshot();
                snapshot.set(newSnapshot);
                loaded = true;
                logger.info("{}", LogFields.kv("event", "BLACKLIST_RELOAD_OK"));

            } catch (Exception e) {
                logger.error("{} error={}", LogFields.kv("event", "BLACKLIST_RELOAD_ERROR"), e.getMessage());
            }
        }
    }

    private void ensureLoaded() {
        if (loaded) return;

        synchronized (reloadLock) {
            if (loaded) return;
            try {
                BlacklistSnapshot newSnapshot = buildSnapshot();
                snapshot.set(newSnapshot);
                logger.info("{}", LogFields.kv("event", "BLACKLIST_FIRST_LOAD_OK"));
            } catch (Exception e) {
                logger.error("Критическая ошибка первой загрузки blacklist. Используется пустой snapshot.", e);
                snapshot.set(BlacklistSnapshot.empty());
            } finally {
                loaded = true;
            }
        }
    }

    private BlacklistSnapshot buildSnapshot() {
        DomainTrie newDomainTrie = new DomainTrie();
        Set<String> newIps = new HashSet<String>();
        int loadedSources = 0;
        int totalRules = 0;
        int invalidRules = 0;
        int duplicateIps = 0;

        for (BlacklistSource source : sources) {
            try {
                long startedAt = System.currentTimeMillis();
                logger.info("{} {}", LogFields.kv("event", "BLACKLIST_SOURCE_LOAD_START"), LogFields.kv("source", source));
                List<String> rules = source.loadRules();
                if (rules == null) {
                    logger.warn("Источник {} вернул null вместо списка правил", source);
                    continue;
                }

                int sourceAcceptedRules = 0;
                int sourceInvalidRules = 0;

                for (String rawRule : rules) {
                    String rule = normalizeRule(rawRule);

                    if (rule == null) {
                        sourceInvalidRules++;
                        continue;
                    }

                    if (isIpLiteral(rule)) {
                        String ip = HostNormalizer.normalizeIp(rule);

                        if (ip == null) {
                            sourceInvalidRules++;
                            logger.debug("Источник {}: пропущен некорректный IP: {}", source, rule);
                            continue;
                        }

                        if (!newIps.add(ip))
                            duplicateIps++;
                        sourceAcceptedRules++;
                        totalRules++;
                        continue;
                    }

                    String domain = HostNormalizer.normalizeHost(rule);

                    if (domain == null) {
                        sourceInvalidRules++;
                        logger.debug("Источник {}: пропущено некорректное доменное правило: {}", source, rule);
                        continue;
                    }

                    if (domain.startsWith("*.")) {
                        String subdomain = domain.substring(2);
                        newDomainTrie.addDomain(subdomain, DomainTrie.MatchType.WILDCARD);
                    } else if (isSubtreeRule(rule, source)) {
                        newDomainTrie.addDomain(domain, DomainTrie.MatchType.SUBTREE);
                    } else {
                        newDomainTrie.addDomain(domain, DomainTrie.MatchType.EXACT);
                    }
                    sourceAcceptedRules++;
                    totalRules++;
                }

                loadedSources++;
                invalidRules += sourceInvalidRules;
                long durationMillis = System.currentTimeMillis() - startedAt;
                logger.info("{} {} {} {} {} {}",
                        LogFields.kv("event", "BLACKLIST_SOURCE_LOADED"),
                        LogFields.kv("source", source),
                        LogFields.kv("rulesReceived", rules.size()),
                        LogFields.kv("rulesAccepted", sourceAcceptedRules),
                        LogFields.kv("rulesInvalid", sourceInvalidRules),
                        LogFields.kv("durationMs", durationMillis));

            } catch (Exception e) {
                logger.error("Не удалось загрузить blacklist из источника {}", source, e);
            }
        }

        if (!sources.isEmpty() && loadedSources == 0)
            throw new IllegalStateException("Не удалось загрузить ни одного источника blacklist");
        Set<String> immutableIps = Set.copyOf(newIps);
        BlacklistSnapshot newSnapshot = new BlacklistSnapshot(newDomainTrie, immutableIps);

        logger.info("{} {} {} {} {} {}",
                LogFields.kv("event", "BLACKLIST_SNAPSHOT_BUILT"),
                LogFields.kv("sourcesLoaded", loadedSources),
                LogFields.kv("rulesTotal", totalRules),
                LogFields.kv("ipsUnique", immutableIps.size()),
                LogFields.kv("ipsDuplicate", duplicateIps),
                LogFields.kv("rulesInvalid", invalidRules));

        return newSnapshot;
    }

    private void startReloadScheduler() {
        if (!getConfig().getBoolean("blacklist.reload.enabled")) {
            logger.info("Периодическое обновление blacklist отключено");
            return;
        }

        int intervalSeconds = getConfig().getInt("blacklist.reload.interval-seconds");

        if (intervalSeconds <= 0) {
            logger.warn(
                    "Периодическое обновление blacklist отключено: некорректный интервал {}",
                    intervalSeconds
            );
            return;
        }

        synchronized (reloadLock) {
            if (reloadExecutor != null && !reloadExecutor.isShutdown())
                return;

            reloadExecutor = Executors.newSingleThreadScheduledExecutor(
                    runnable -> {
                        Thread thread = new Thread(runnable, "Blacklist-Reload-Thread");
                        thread.setDaemon(true);
                        return thread;
                    }
            );

            reloadExecutor.scheduleWithFixedDelay(this::reloadNow, intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
            logger.info("Периодическое обновление blacklist включено: каждые {} секунд", intervalSeconds);
        }
    }

    private static String normalizeRule(String value) {
        if (value == null) return null;
        String result = value.trim();
        if (result.isEmpty() || result.startsWith("#") || result.startsWith("!")) return null;
        int commentIndex = result.indexOf('#');

        if (commentIndex >= 0)
            result = result.substring(0, commentIndex).trim();

        return result.isEmpty() ? null : result;
    }

    private static boolean isIpLiteral(String value) {
        if (value == null || value.isEmpty()) return false;
        if (value.indexOf(':') >= 0) return true;
        return isIpv4Literal(value);
    }

    private static boolean isIpv4Literal(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) {
            if (part.isEmpty()) return false;


            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i))) return false;
            }

            try {
                int number = Integer.parseInt(part);
                if (number < 0 || number > 255)
                    return false;

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

        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS))
                executor.shutdownNow();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
        logger.info("{}", LogFields.kv("event", "BLACKLIST_RELOAD_SCHEDULER_STOPPED"));
    }

    private static boolean isSubtreeRule(String rule, BlacklistSource source) {
        // RKN всегда subtree
        if (source instanceof RknBlacklistSource)
            return true;

        // Остальные источники — exact
        return false;
    }
}