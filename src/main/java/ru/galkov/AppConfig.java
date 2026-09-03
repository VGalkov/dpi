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
 * Оптимизированный конфиг (singleton).
 * - Предзагрузка всех значений при старте
 * - Единый кэш для всех типов
 * - Быстрый доступ через getInstance()
 */
public final class AppConfig {
    private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);
    private static final String DEFAULT_PATH = "application.properties";

    // 🔵 Singleton
    private static volatile AppConfig instance;
    private static final Object INIT_LOCK = new Object();

    // 🔵 Единый кэш для всех типов
    private final ConcurrentHashMap<String, Object> cache = new ConcurrentHashMap<>(512);

    // 🔵 Properties только для инициализации
    private final Properties props;

    private AppConfig(String path) throws IOException {
        this.props = load(path);
        if (this.props.isEmpty()) throw new IOException("Config is empty");
        preloadCache();
        validateConfig();
    }

    // ============================================================
    // SINGLETON
    // ============================================================

    public static AppConfig getInstance() {
        AppConfig local = instance;
        if (local != null) return local;

        synchronized (INIT_LOCK) {
            if (instance != null) return instance;

            String path = System.getProperty("config.path", DEFAULT_PATH);
            try {
                LocaleUtil.reload();
                logger.info(LocaleUtil.getString("config_attempt_load"), path);
                instance = new AppConfig(path);
                return instance;
            } catch (IOException e) {
                logger.error("Config initialization failed", e);
                throw new IllegalStateException("Config not initialized", e);
            }
        }
    }

    // ============================================================
    // МЕТОДЫ ДОСТУПА (с проверкой типа)
    // ============================================================

    public int getInt(String key) {
        Object cached = cache.get(key);
        if (cached instanceof Integer) return (Integer) cached;
        if (cached instanceof String) {
            int value = Integer.parseInt((String) cached);
            cache.put(key, value);
            return value;
        }
        return parseInt(key, getRequired(key));
    }

    public long getLong(String key) {
        Object cached = cache.get(key);
        if (cached instanceof Long) return (Long) cached;
        if (cached instanceof String) {
            long value = Long.parseLong((String) cached);
            cache.put(key, value);
            return value;
        }
        return parseLong(key, getRequired(key));
    }

    public boolean getBoolean(String key) {
        Object cached = cache.get(key);
        if (cached instanceof Boolean) return (Boolean) cached;
        if (cached instanceof String) {
            boolean value = Boolean.parseBoolean((String) cached);
            cache.put(key, value);
            return value;
        }
        return parseBoolean(key, getRequired(key));
    }

    public double getDouble(String key) {
        Object cached = cache.get(key);
        if (cached instanceof Double) return (Double) cached;
        if (cached instanceof String) {
            double value = Double.parseDouble((String) cached);
            cache.put(key, value);
            return value;
        }
        return parseDouble(key, getRequired(key));
    }

    public String get(String key) {
        Object cached = cache.get(key);
        if (cached instanceof String) return (String) cached;
        return parseString(key, getRequired(key));
    }

    public String getOptional(String key) {
        Object cached = cache.get(key);
        if (cached instanceof String) return (String) cached;
        String value = props.getProperty(key);
        return value != null ? parseString(key, trimComment(value)) : null;
    }

    @SuppressWarnings("unchecked")
    public List<String> getList(String key) {
        Object cached = cache.get(key);
        if (cached instanceof List) return (List<String>) cached;
        if (cached instanceof String) {
            List<String> value = parseListValue((String) cached);
            cache.put(key, value);
            return value;
        }
        return parseList(key, getOptional(key));
    }

    @SuppressWarnings("unchecked")
    public Set<Integer> getIntSet(String key) {
        Object cached = cache.get(key);
        if (cached instanceof Set) return (Set<Integer>) cached;
        if (cached instanceof String) {
            Set<Integer> value = parseIntSetValue((String) cached);
            cache.put(key, value);
            return value;
        }
        return parseIntSet(key, getOptional(key));
    }

    @SuppressWarnings("unchecked")
    public List<Integer> getIntList(String key) {
        Object cached = cache.get(key);
        if (cached instanceof List) return (List<Integer>) cached;
        if (cached instanceof String) {
            List<Integer> value = parseIntListValue((String) cached);
            cache.put(key, value);
            return value;
        }
        return parseIntList(key, getOptional(key));
    }

    // ============================================================
    // ЗАГРУЗКА
    // ============================================================

    private Properties load(String path) throws IOException {
        Properties raw = new Properties();
        File configFile = new File(path);
        boolean loadedFromFile = false;

        if (configFile.exists() && configFile.isFile()) {
            logger.info(LocaleUtil.getString("config_found_disk"), configFile.getAbsolutePath());
            try (FileInputStream fis = new FileInputStream(configFile)) {
                raw.load(fis);
                loadedFromFile = true;
            } catch (IOException e) {
                logger.warn(LocaleUtil.getString("config_load_error"), e.getMessage());
            }
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
                throw new IllegalStateException(LocaleUtil.getString("config_critical_not_found"));
            }
        }

        if (raw.isEmpty()) throw new IOException(LocaleUtil.getString("config_empty"));

        Properties expanded = new Properties(raw.size());
        for (String key : raw.stringPropertyNames()) {
            String value = raw.getProperty(key);
            if (value != null) {
                expanded.setProperty(key, resolveValue(value.trim(), raw, new HashSet<>()));
            }
        }
        return expanded;
    }

    private void preloadCache() {
        for (String key : props.stringPropertyNames()) {
            String value = props.getProperty(key);
            if (value != null) {
                cache.put(key, trimComment(value.trim()));
            }
        }
    }

    // ============================================================
    // ВАЛИДАЦИЯ
    // ============================================================

    private void validateConfig() {
        logger.info(LocaleUtil.getString("config_validation_started"));

        validateIntRange("dns.local.port", 1, 65535, 53);
        validateIntRange("dns.thread.num", 1, 1000, 50);
        validateIntRange("dns.timeout", 1, 300, 3);
        validateIntRange("proxy.max-header-bytes", 1024, 1048576, 32768);
        validateLongRange("proxy.max-body-bytes", 0, 10995116277760L, 10485760L);
        validateIntRange("proxy.connect-timeout-millis", 1000, 60000, 10000);
        validateIntRange("proxy.max-connections", 1, 10000, 500);
        validateIntRange("dns.rate-limit.requests-per-second", 1, 10000, 100);
        validateIntRange("dns.rate-limit.burst", 1, 20000, 200);
        validateIntRange("blacklist.reload.interval-seconds", 20, 259200, 86400);
        validateDoubleRange("dns.anomaly-detector.trust-threshold", 0.0, 1.0, 0.7);

        validateSecuritySettings();
        logger.info(LocaleUtil.getString("config_validation_completed"));
    }

    private void validateIntRange(String key, int min, int max, int def) {
        try {
            int value = getInt(key);
            if (value < min || value > max) {
                logger.warn("Config {} = {} out of range [{},{}], using {}", key, value, min, max, def);
                cache.put(key, def);
            }
        } catch (Exception e) {
            logger.warn("Config {} invalid, using {}", key, def);
            cache.put(key, def);
        }
    }

    private void validateLongRange(String key, long min, long max, long def) {
        try {
            long value = getLong(key);
            if (value < min || value > max) {
                logger.warn("Config {} = {} out of range, using {}", key, value, def);
                cache.put(key, def);
            }
        } catch (Exception e) {
            cache.put(key, def);
        }
    }

    private void validateDoubleRange(String key, double min, double max, double def) {
        try {
            double value = getDouble(key);
            if (value < min || value > max) {
                logger.warn("Config {} = {} out of range, using {}", key, value, def);
                cache.put(key, def);
            }
        } catch (Exception e) {
            cache.put(key, def);
        }
    }

    private void validateSecuritySettings() {
        String dnsLlmUrl = getOptional("dns.anomaly-detector.llm-studio.url");
        if (dnsLlmUrl != null && (dnsLlmUrl.contains("localhost") || dnsLlmUrl.contains("127.0.0.1"))) {
            logger.warn("⚠️ SECURITY: DNS LLM URL points to localhost: {}", dnsLlmUrl);
        }

        String adguardUrl = getOptional("blacklist.adguard.url");
        if (adguardUrl != null && adguardUrl.startsWith("http://")) {
            logger.warn("⚠️ SECURITY: AdGuard URL uses HTTP: {}", adguardUrl);
        }

        int dnsThreads = getInt("dns.thread.num");
        if (dnsThreads > 200) {
            logger.warn("⚠️ PERFORMANCE: dns.thread.num = {} too high, recommended 50-150", dnsThreads);
        }
    }

    // ============================================================
    // УТИЛИТЫ
    // ============================================================

    private String getRequired(String key) {
        String val = props.getProperty(key);
        if (val == null) throw new IllegalStateException(LocaleUtil.getString("key_not_found", key));
        return trimComment(val.trim());
    }

    private static String trimComment(String value) {
        if (value == null) return null;
        int idx = value.indexOf('#');
        return idx >= 0 ? value.substring(0, idx).trim() : value.trim();
    }

    private static String resolveValue(String value, Properties raw, Set<String> resolving) {
        int start = value.indexOf("${");
        if (start < 0) return value;

        int end = value.indexOf('}', start);
        if (end < 0) throw new IllegalArgumentException("Unpaired placeholder: " + value);

        String keyInside = value.substring(start + 2, end).trim();
        if (!resolving.add(keyInside))
            throw new IllegalStateException("Cyclic config reference: " + resolving + " -> " + keyInside);

        try {
            String replacement = raw.getProperty(keyInside);
            if (replacement == null)
                throw new IllegalStateException("Value not found for key: " + keyInside);

            String resolved = resolveValue(replacement, raw, resolving);
            return resolveValue(value.substring(0, start) + resolved + value.substring(end + 1), raw, resolving);
        } finally {
            resolving.remove(keyInside);
        }
    }

    // 🔵 Парсинг и кэширование
    private int parseInt(String key, String value) {
        int result = Integer.parseInt(value);
        cache.put(key, result);
        return result;
    }

    private long parseLong(String key, String value) {
        long result = Long.parseLong(value);
        cache.put(key, result);
        return result;
    }

    private boolean parseBoolean(String key, String value) {
        boolean result = Boolean.parseBoolean(value);
        cache.put(key, result);
        return result;
    }

    private double parseDouble(String key, String value) {
        double result = Double.parseDouble(value);
        cache.put(key, result);
        return result;
    }

    private String parseString(String key, String value) {
        cache.put(key, value);
        return value;
    }

    private List<String> parseList(String key, String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            List<String> empty = Collections.emptyList();
            cache.put(key, empty);
            return empty;
        }
        String[] parts = raw.trim().split("\\s*,\\s*");
        List<String> result = new ArrayList<>(parts.length);
        for (String p : parts) {
            if (!p.isEmpty()) result.add(p);
        }
        result = Collections.unmodifiableList(result);
        cache.put(key, result);
        return result;
    }

    private Set<Integer> parseIntSet(String key, String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            Set<Integer> empty = Collections.emptySet();
            cache.put(key, empty);
            return empty;
        }
        String[] parts = raw.trim().split("\\s*,\\s*");
        Set<Integer> result = new LinkedHashSet<>(parts.length);
        for (String p : parts) {
            if (!p.isEmpty()) result.add(Integer.parseInt(p.trim()));
        }
        result = Collections.unmodifiableSet(result);
        cache.put(key, result);
        return result;
    }

    private List<Integer> parseIntList(String key, String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            List<Integer> empty = Collections.emptyList();
            cache.put(key, empty);
            return empty;
        }
        String[] parts = raw.trim().split("\\s*,\\s*");
        List<Integer> result = new ArrayList<>(parts.length);
        for (String p : parts) {
            if (!p.isEmpty()) result.add(Integer.parseInt(p.trim()));
        }
        result = Collections.unmodifiableList(result);
        cache.put(key, result);
        return result;
    }

    // 🔵 Вспомогательные методы для парсинга из String (без ключа)
    private List<String> parseListValue(String raw) {
        if (raw == null || raw.trim().isEmpty()) return Collections.emptyList();
        String[] parts = raw.trim().split("\\s*,\\s*");
        List<String> result = new ArrayList<>(parts.length);
        for (String p : parts) {
            if (!p.isEmpty()) result.add(p);
        }
        return Collections.unmodifiableList(result);
    }

    private Set<Integer> parseIntSetValue(String raw) {
        if (raw == null || raw.trim().isEmpty()) return Collections.emptySet();
        String[] parts = raw.trim().split("\\s*,\\s*");
        Set<Integer> result = new LinkedHashSet<>(parts.length);
        for (String p : parts) {
            if (!p.isEmpty()) result.add(Integer.parseInt(p.trim()));
        }
        return Collections.unmodifiableSet(result);
    }

    private List<Integer> parseIntListValue(String raw) {
        if (raw == null || raw.trim().isEmpty()) return Collections.emptyList();
        String[] parts = raw.trim().split("\\s*,\\s*");
        List<Integer> result = new ArrayList<>(parts.length);
        for (String p : parts) {
            if (!p.isEmpty()) result.add(Integer.parseInt(p.trim()));
        }
        return Collections.unmodifiableList(result);
    }
}