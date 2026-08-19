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

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class AppConfig {
    private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);
    private static final String DEFAULT_PATH = "application.properties";
    private final Properties props;

    // ✅ П.27: Кэш для parsed значений
    private final Map<String, Integer> intCache = new ConcurrentHashMap<>(256);
    private final Map<String, Long> longCache = new ConcurrentHashMap<>(256);
    private final Map<String, Boolean> booleanCache = new ConcurrentHashMap<>(256);
    private final Map<String, List<String>> listCache = new ConcurrentHashMap<>(64);

    private AppConfig(String path) throws IOException {
        this.props = load(path);
        if (this.props.isEmpty()) {
            throw new IOException("Config is null or empty after load");
        }
        validateConfig();
    }

    private static class Holder {
        private static AppConfig INSTANCE;
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

        try {
            if (configFile.exists() && configFile.isFile()) {
                logger.info(LocaleUtil.getString("config_found_disk"), configFile.getAbsolutePath());
                try (FileInputStream fis = new FileInputStream(configFile)) {
                    raw.load(fis);
                }
            } else {
                logger.warn(LocaleUtil.getString("config_not_found_disk"), path);
                URL resourceUrl = AppConfig.class.getResource("/application.properties");
                if (resourceUrl != null) {
                    logger.info(LocaleUtil.getString("config_found_jar"));
                    try (InputStream is = resourceUrl.openStream()) {
                        raw.load(is);
                    }
                } else {
                    throw new IllegalStateException(LocaleUtil.getString("config_critical_not_found"));
                }
            }
            if (raw.isEmpty()) throw new IOException(LocaleUtil.getString("config_empty"));
        } catch (IOException e) {
            logger.error(LocaleUtil.getString("config_load_error"), e);
            throw e;
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

    /**
     * ✅ П.20: Оптимизация валидации — единый метод для всех типов
     */
    private void validateConfig() {
        logger.info(LocaleUtil.getString("config_validation_started"));

        // DNS настройки
        validateIntRange("dns.local.port", 1, 65535, 53, "config_validation_dns_port_invalid");
        validateIntRange("dns.thread.num", 1, 1000, 50, "config_validation_dns_threads_invalid");
        validateIntRange("dns.timeout", 1, 300, 3, "config_validation_dns_timeout_invalid");

        // Proxy настройки
        validateIntRange("proxy.local.port", 1, 65535, 8888, "config_validation_proxy_port_invalid");
        validateIntRange("proxy.max-header-bytes", 1024, 1048576, 32768, "config_validation_proxy_max_header_invalid");
        validateLongRange("proxy.max-body-bytes", 0, 1073741824, 10485760, "config_validation_proxy_max_body_invalid");
        validateIntRange("proxy.connect-timeout-millis", 1000, 60000, 10000, "config_validation_proxy_connect_timeout_invalid");
        validateIntRange("proxy.max-connections", 1, 10000, 500, "config_validation_proxy_max_conn_invalid");

        // Proxy max-connections-per-client (зависит от max-connections)
        validateDependentIntRange("proxy.max-connections-per-client", 1, getInt("proxy.max-connections"), 20,
                "config_validation_proxy_max_conn_client_invalid", "proxy.max-connections");

        // DNS Rate Limit
        validateIntRange("dns.rate-limit.requests-per-second", 1, 10000, 100, "config_validation_dns_rate_limit_rps_invalid");
        validateIntRange("dns.rate-limit.burst", 1, 20000, 200, "config_validation_dns_rate_limit_burst_invalid");
        validateIntRange("dns.rate-limit.client-idle-seconds", 60, 3600, 300, "config_validation_dns_rate_limit_idle_invalid");

        // Anomaly Detectors
        validateDoubleRange("dns.anomaly-detector.trust-threshold", 0.0, 1.0, 0.7, "config_validation_dns_trust_threshold_invalid");
        validateIntRange("dns.anomaly-detector.processed-ttl-seconds", 60, 86400, 60, "config_validation_dns_ttl_invalid");
        validateIntRange("http.anomaly-detector.processed-ttl-seconds", 60, 86400, 3600, "config_validation_http_ttl_invalid");

        // Blacklist reload
        validateIntRange("blacklist.reload.interval-seconds", 300, 86400, 36000, "config_validation_blacklist_reload_invalid");

        logger.info(LocaleUtil.getString("config_validation_completed"));
    }

    /**
     * ✅ П.20: Единый метод валидации int диапазона
     */
    private void validateIntRange(String key, int min, int max, int defaultValue, String errorKey) {
        try {
            int value = getInt(key);
            if (value < min || value > max) {
                logger.warn(LocaleUtil.getString(errorKey, key, value, min, max));
                props.setProperty(key, String.valueOf(defaultValue));
            }
        } catch (Exception e) {
            logger.warn(LocaleUtil.getString(errorKey, key, "N/A", min, max));
            props.setProperty(key, String.valueOf(defaultValue));
        }
    }

    /**
     * ✅ П.20: Валидация int с зависимостью от другого ключа
     */
    private void validateDependentIntRange(String key, int min, int maxFromOtherKey, int defaultValue, String errorKey, String dependencyKey) {
        try {
            int value = getInt(key);
            if (value < min || value > maxFromOtherKey) {
                logger.warn(LocaleUtil.getString(errorKey, key, value, min, maxFromOtherKey));
                props.setProperty(key, String.valueOf(defaultValue));
            }
        } catch (Exception e) {
            logger.warn(LocaleUtil.getString(errorKey, key, "N/A", min, maxFromOtherKey));
            props.setProperty(key, String.valueOf(defaultValue));
        }
    }

    /**
     * ✅ П.20: Единый метод валидации long диапазона
     */
    private void validateLongRange(String key, long min, long max, long defaultValue, String errorKey) {
        try {
            long value = getLong(key);
            if (value < min || value > max) {
                logger.warn(LocaleUtil.getString(errorKey, key, value, min, max));
                props.setProperty(key, String.valueOf(defaultValue));
            }
        } catch (Exception e) {
            logger.warn(LocaleUtil.getString(errorKey, key, "N/A", min, max));
            props.setProperty(key, String.valueOf(defaultValue));
        }
    }

    /**
     * ✅ П.20: Единый метод валидации double диапазона
     */
    private void validateDoubleRange(String key, double min, double max, double defaultValue, String errorKey) {
        try {
            double value = Double.parseDouble(get(key));
            if (value < min || value > max) {
                logger.warn(LocaleUtil.getString(errorKey, key, value, min, max));
                props.setProperty(key, String.valueOf(defaultValue));
            }
        } catch (Exception e) {
            logger.warn(LocaleUtil.getString(errorKey, key, "N/A", min, max));
            props.setProperty(key, String.valueOf(defaultValue));
        }
    }

    private String resolveValue(String value, Properties raw) {
        if (value == null || raw == null) return value;
        while (value.contains("${")) {
            int start = value.indexOf("${");
            if (start < 0) break;
            int end = value.indexOf('}', start);
            if (end < 0) throw new IllegalArgumentException(LocaleUtil.getString("unpaired_placeholder", value));
            String keyInside = value.substring(start + 2, end).trim();
            String replacement = raw.getProperty(keyInside);
            if (replacement == null) throw new IllegalStateException(LocaleUtil.getString("value_not_found_for_key", keyInside));
            value = value.substring(0, start) + resolveValue(replacement, raw) + value.substring(end + 1);
        }
        return value;
    }

    public String get(String key) {
        if (props == null) {
            throw new IllegalStateException("Properties not loaded");
        }
        String val = props.getProperty(key);
        if (val == null) throw new IllegalStateException(LocaleUtil.getString("key_not_found", key));
        return val;
    }

    public List<String> getList(String key) {
        // ✅ П.27: Кэш для list
        List<String> cached = listCache.get(key);
        if (cached != null) return cached;

        String raw = get(key).trim();
        if (raw.isEmpty()) {
            listCache.put(key, Collections.emptyList());
            return Collections.emptyList();
        }
        Set<String> seen = new LinkedHashSet<>();
        for (String part : raw.split("\\s*,\\s*")) {
            String value = part.trim();
            if (!value.isEmpty()) seen.add(value);
        }
        List<String> result = List.copyOf(seen);
        listCache.put(key, result);
        return result;
    }

    public Set<String> getSet(String key) {
        return new HashSet<>(getList(key));
    }

    /**
     * ✅ П.27: Кэш для int значений
     */
    public int getInt(String key) {
        Integer cached = intCache.get(key);
        if (cached != null) return cached;

        int value = Integer.parseInt(get(key));
        intCache.put(key, value);
        return value;
    }

    /**
     * ✅ П.27: Кэш для long значений
     */
    public long getLong(String key) {
        Long cached = longCache.get(key);
        if (cached != null) return cached;

        long value = Long.parseLong(get(key));
        longCache.put(key, value);
        return value;
    }

    /**
     * ✅ П.27: Кэш для boolean значений
     */
    public boolean getBoolean(String key) {
        Boolean cached = booleanCache.get(key);
        if (cached != null) return cached;

        boolean value = Boolean.parseBoolean(get(key));
        booleanCache.put(key, value);
        return value;
    }

    public Short getShort(String key) {
        return Short.valueOf(get(key));
    }
}