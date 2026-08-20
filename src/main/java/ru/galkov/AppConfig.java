package ru.galkov;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class AppConfig {
    private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);
    private static final String DEFAULT_PATH = "application.properties";

    private static final int INT_CACHE_MAX = 512;
    private static final int LONG_CACHE_MAX = 512;
    private static final int BOOLEAN_CACHE_MAX = 256;
    private static final int LIST_CACHE_MAX = 128;
    private static final int SHORT_CACHE_MAX = 128;

    private final Properties props;

    private final Map<String, Integer> intCache = new ConcurrentHashMap<>(256);
    private final Map<String, Long> longCache = new ConcurrentHashMap<>(256);
    private final Map<String, Boolean> booleanCache = new ConcurrentHashMap<>(256);
    private final Map<String, List<String>> listCache = new ConcurrentHashMap<>(64);
    private final Map<String, Short> shortCache = new ConcurrentHashMap<>(64);

    private AppConfig(String path) throws IOException {
        this.props = load(path);
        if (this.props.isEmpty()) {
            throw new IOException("Config is null or empty after load");
        }
        validateConfig();
    }

    private static class Holder {
        private static volatile AppConfig INSTANCE;
    }

    public static synchronized AppConfig getInstance() throws IOException {
        String path = System.getProperty("config.path", DEFAULT_PATH);
        if (Holder.INSTANCE == null) {
            LocaleUtil.reload();
            logger.info(LocaleUtil.getString("config_attempt_load"), path);
            Holder.INSTANCE = new AppConfig(path);
        }
        return Holder.INSTANCE;
    }

    private synchronized Properties load(String path) throws IOException {
        Properties raw = new Properties();
        File configFile = new File(path);

        boolean loadedFromFile = false;

        try {
            if (configFile.exists() && configFile.isFile()) {
                logger.info(
                        LocaleUtil.getString("config_found_disk"),
                        configFile.getAbsolutePath()
                );
                try (FileInputStream fis = new FileInputStream(configFile)) {
                    raw.load(fis);
                    loadedFromFile = true;
                }
            }
        } catch (IOException e) {
            logger.warn(
                    LocaleUtil.getString("config_load_error"),
                    e.getMessage()
            );
            loadedFromFile = false;
        }

        if (!loadedFromFile || raw.isEmpty()) {
            logger.warn(LocaleUtil.getString("config_not_found_disk"), path);
            URL resourceUrl = AppConfig.class.getResource("/application.properties");
            if (resourceUrl != null) {
                logger.info(LocaleUtil.getString("config_found_jar"));
                try (InputStream is = resourceUrl.openStream()) {
                    raw.load(is);
                }
            } else {
                throw new IllegalStateException(
                        LocaleUtil.getString("config_critical_not_found")
                );
            }
        }

        if (raw.isEmpty()) {
            throw new IOException(LocaleUtil.getString("config_empty"));
        }

        Properties expanded = new Properties();
        for (String key : raw.stringPropertyNames()) {
            String value = raw.getProperty(key);
            if (value != null) {
                expanded.setProperty(key, resolveValue(value.trim(), raw));
            }
        }
        if (expanded.isEmpty()) {
            throw new IOException("Config is empty after expansion");
        }
        return expanded;
    }

    private void validateConfig() {
        logger.info(LocaleUtil.getString("config_validation_started"));

        validateIntRange(
                "dns.local.port", 1, 65535, 53,
                "config_validation_dns_port_invalid");
        validateIntRange(
                "dns.thread.num", 1, 1000, 50,
                "config_validation_dns_threads_invalid");
        validateIntRange(
                "dns.timeout", 1, 300, 3,
                "config_validation_dns_timeout_invalid");

        validateIntRange(
                "proxy.local.port", 1, 65535, 8888,
                "config_validation_proxy_port_invalid");
        validateIntRange(
                "proxy.max-header-bytes", 1024, 1048576, 32768,
                "config_validation_proxy_max_header_invalid");
        validateLongRange(
                "proxy.max-body-bytes", 0, 10995116277760L, 10485760L,
                "config_validation_proxy_max_body_invalid");
        validateIntRange(
                "proxy.connect-timeout-millis", 1000, 60000, 10000,
                "config_validation_proxy_connect_timeout_invalid");
        validateIntRange(
                "proxy.max-connections", 1, 10000, 500,
                "config_validation_proxy_max_conn_invalid");

        validateDependentIntRange(
                "proxy.max-connections-per-client",
                1,
                getInt("proxy.max-connections"),
                20,
                "config_validation_proxy_max_conn_client_invalid"
        );

        validateIntRange(
                "dns.rate-limit.requests-per-second", 1, 10000, 100,
                "config_validation_dns_rate_limit_rps_invalid");
        validateIntRange(
                "dns.rate-limit.burst", 1, 20000, 200,
                "config_validation_dns_rate_limit_burst_invalid");
        validateIntRange(
                "dns.rate-limit.client-idle-seconds", 60, 3600, 300,
                "config_validation_dns_rate_limit_idle_invalid");

        validateDoubleRange(
                "dns.anomaly-detector.trust-threshold", 0.0, 1.0, 0.7,
                "config_validation_dns_trust_threshold_invalid");
        validateIntRange(
                "dns.anomaly-detector.processed-ttl-seconds", 60, 86400, 60,
                "config_validation_dns_ttl_invalid");
        validateIntRange(
                "http.anomaly-detector.processed-ttl-seconds", 60, 86400, 3600,
                "config_validation_http_ttl_invalid");

        validateIntRange(
                "blacklist.reload.interval-seconds", 300, 86400, 36000,
                "config_validation_blacklist_reload_invalid");

        validateSecuritySettings();

        clearCaches();

        logger.info(LocaleUtil.getString("config_validation_completed"));
    }

    private void validateSecuritySettings() {
        String dnsLlmUrl = getOptional("dns.anomaly-detector.llm-studio.url");
        if (dnsLlmUrl != null
                && (dnsLlmUrl.contains("localhost")
                || dnsLlmUrl.contains("127.0.0.1"))) {
            logger.warn(
                    "⚠️ SECURITY WARNING: DNS LLM URL указывает на localhost: {}. "
                            + "Это может быть опасно в production",
                    dnsLlmUrl);
        }

        String httpLlmUrl = getOptional("http.anomaly-detector.llm-studio.url");
        if (httpLlmUrl != null
                && (httpLlmUrl.contains("localhost")
                || httpLlmUrl.contains("127.0.0.1"))) {
            logger.warn(
                    "⚠️ SECURITY WARNING: HTTP LLM URL указывает на localhost: {}. "
                            + "Это может быть опасно в production",
                    httpLlmUrl);
        }

        String adguardUrl = getOptional("blacklist.adguard.url");
        if (adguardUrl != null && adguardUrl.startsWith("http://")) {
            logger.warn(
                    "⚠️ SECURITY WARNING: AdGuard blacklist URL использует HTTP (не HTTPS): {}. "
                            + "Возможна MITM атака",
                    adguardUrl);
        }

        String mvpsUrl = getOptional("blacklist.mvps_hosts.url");
        if (mvpsUrl != null && mvpsUrl.startsWith("http://")) {
            logger.warn(
                    "⚠️ SECURITY WARNING: MVPS hosts URL использует HTTP (не HTTPS): {}. "
                            + "Возможна MITM атака",
                    mvpsUrl);
        }

        int dnsThreads = getInt("dns.thread.num");
        if (dnsThreads > 200) {
            logger.warn(
                    "⚠️ PERFORMANCE WARNING: dns.thread.num = {} может быть слишком высоким. "
                            + "Рекомендуется 50-150",
                    dnsThreads);
        }

        int maxConnections = getInt("proxy.max-connections");
        int maxPerClient = getInt("proxy.max-connections-per-client");
        if (maxPerClient > maxConnections / 10) {
            logger.warn(
                    "⚠️ PERFORMANCE WARNING: proxy.max-connections-per-client ({}) "
                            + "слишком высок относительно max-connections ({}). "
                            + "Рекомендуется <= 10% от max-connections",
                    maxPerClient,
                    maxConnections);
        }
    }

    private void validateIntRange(
            String key, int min, int max, int defaultValue, String errorKey) {
        try {
            int value = getInt(key);
            if (value < min || value > max) {
                logger.warn(LocaleUtil.getString(errorKey, key, value, min, max));
                props.setProperty(key, String.valueOf(defaultValue));
                clearCaches();
            }
        } catch (Exception e) {
            logger.warn(LocaleUtil.getString(errorKey, key, "N/A", min, max));
            props.setProperty(key, String.valueOf(defaultValue));
            clearCaches();
        }
    }

    private void validateDependentIntRange(
            String key, int min, int maxFromOtherKey, int defaultValue,
            String errorKey) {
        try {
            int value = getInt(key);
            if (value < min || value > maxFromOtherKey) {
                logger.warn(
                        LocaleUtil.getString(errorKey, key, value, min, maxFromOtherKey));
                props.setProperty(key, String.valueOf(defaultValue));
                clearCaches();
            }
        } catch (Exception e) {
            logger.warn(
                    LocaleUtil.getString(errorKey, key, "N/A", min, maxFromOtherKey));
            props.setProperty(key, String.valueOf(defaultValue));
            clearCaches();
        }
    }

    private void validateLongRange(
            String key, long min, long max, long defaultValue, String errorKey) {
        try {
            long value = getLong(key);
            if (value < min || value > max) {
                logger.warn(LocaleUtil.getString(errorKey, key, value, min, max));
                props.setProperty(key, String.valueOf(defaultValue));
                clearCaches();
            }
        } catch (Exception e) {
            logger.warn(LocaleUtil.getString(errorKey, key, "N/A", min, max));
            props.setProperty(key, String.valueOf(defaultValue));
            clearCaches();
        }
    }

    private void validateDoubleRange(
            String key, double min, double max, double defaultValue, String errorKey) {
        try {
            String valueStr = getOptional(key);
            if (valueStr == null) {
                props.setProperty(key, String.valueOf(defaultValue));
                clearCaches();
                return;
            }

            double value = Double.parseDouble(valueStr);
            if (value < min || value > max) {
                logger.warn(LocaleUtil.getString(errorKey, key, value, min, max));
                props.setProperty(key, String.valueOf(defaultValue));
                clearCaches();
            }
        } catch (Exception e) {
            logger.warn(LocaleUtil.getString(errorKey, key, "N/A", min, max));
            props.setProperty(key, String.valueOf(defaultValue));
            clearCaches();
        }
    }

    private String resolveValue(String value, Properties raw) {
        return resolveValue(value, raw, new HashSet<>());
    }

    private String resolveValue(String value, Properties raw, Set<String> resolvingKeys) {
        if (value == null || raw == null) {
            return value;
        }

        int start = value.indexOf("${");
        if (start < 0) {
            return value;
        }

        int end = value.indexOf('}', start);
        if (end < 0) {
            throw new IllegalArgumentException(
                    LocaleUtil.getString("unpaired_placeholder", value));
        }

        String keyInside = value.substring(start + 2, end).trim();

        if (!resolvingKeys.add(keyInside)) {
            throw new IllegalStateException(
                    "Cyclic config reference: " + resolvingKeys + " -> " + keyInside);
        }

        try {
            String replacement = raw.getProperty(keyInside);
            if (replacement == null) {
                throw new IllegalStateException(
                        LocaleUtil.getString("value_not_found_for_key", keyInside));
            }

            String resolvedReplacement = resolveValue(replacement, raw, resolvingKeys);

            String result = value.substring(0, start)
                    + resolvedReplacement
                    + value.substring(end + 1);

            return resolveValue(result, raw, resolvingKeys);
        } finally {
            resolvingKeys.remove(keyInside);
        }
    }

    private void clearCaches() {
        intCache.clear();
        longCache.clear();
        booleanCache.clear();
        listCache.clear();
        shortCache.clear();
    }

    public String get(String key) {
        if (props == null) {
            throw new IllegalStateException("Properties not loaded");
        }
        String val = props.getProperty(key);
        if (val == null) {
            throw new IllegalStateException(LocaleUtil.getString("key_not_found", key));
        }
        return val;
    }

    public String getOptional(String key) {
        if (props == null) {
            return null;
        }
        return props.getProperty(key);
    }

    public List<String> getList(String key) {
        List<String> cached = listCache.get(key);
        if (cached != null) {
            return cached;
        }

        String raw = getOptional(key);
        if (raw == null || raw.trim().isEmpty()) {
            listCache.put(key, Collections.emptyList());
            return Collections.emptyList();
        }

        raw = raw.trim();
        Set<String> seen = new LinkedHashSet<>();
        for (String part : raw.split("\\s*,\\s*")) {
            String value = part.trim();
            if (!value.isEmpty()) {
                seen.add(value);
            }
        }
        List<String> result = List.copyOf(seen);

        if (listCache.size() < LIST_CACHE_MAX) {
            listCache.put(key, result);
        }
        return result;
    }

    public int getInt(String key) {
        Integer cached = intCache.get(key);
        if (cached != null) {
            return cached;
        }

        String raw = get(key);
        String cleaned = trimComment(raw);
        int value = Integer.parseInt(cleaned);

        if (intCache.size() < INT_CACHE_MAX) {
            intCache.put(key, value);
        }
        return value;
    }

    public long getLong(String key) {
        Long cached = longCache.get(key);
        if (cached != null) {
            return cached;
        }

        String raw = get(key);
        String cleaned = trimComment(raw);
        long value = Long.parseLong(cleaned);

        if (longCache.size() < LONG_CACHE_MAX) {
            longCache.put(key, value);
        }
        return value;
    }

    public boolean getBoolean(String key) {
        Boolean cached = booleanCache.get(key);
        if (cached != null) {
            return cached;
        }

        boolean value = Boolean.parseBoolean(get(key));
        if (booleanCache.size() < BOOLEAN_CACHE_MAX) {
            booleanCache.put(key, value);
        }
        return value;
    }

    public short getShort(String key) {
        Short cached = shortCache.get(key);
        if (cached != null) {
            return cached;
        }

        String raw = get(key);
        String cleaned = trimComment(raw);
        short value = Short.parseShort(cleaned);

        if (shortCache.size() < SHORT_CACHE_MAX) {
            shortCache.put(key, value);
        }
        return value;
    }

    private static String trimComment(String value) {
        if (value == null) {
            return null;
        }
        int idx = value.indexOf('#');
        if (idx >= 0) {
            value = value.substring(0, idx);
        }
        return value.trim();
    }

}