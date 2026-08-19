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

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class AppConfig {
    private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);
    private static final String DEFAULT_PATH = "application.properties";
    private final Properties props;

    private AppConfig(String path) throws IOException {
        this.props = load(path);
        if (this.props.isEmpty()) {
            throw new IOException("Config is null or empty after load");
        }
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
        String raw = get(key).trim();
        if (raw.isEmpty()) return Collections.emptyList();
        Set<String> seen = new LinkedHashSet<>();
        for (String part : raw.split("\\s*,\\s*")) {
            String value = part.trim();
            if (!value.isEmpty()) seen.add(value);
        }
        return List.copyOf(seen);
    }

    public Set<String> getSet(String key) {
        return new HashSet<>(getList(key));
    }

    public int getInt(String key) {
        return Integer.parseInt(get(key));
    }

    public long getLong(String key) {
        return Long.parseLong(get(key));
    }

    public boolean getBoolean(String key) {
        return Boolean.parseBoolean(get(key));
    }

    public Short getShort(String key) {
        return Short.valueOf(get(key));
    }
}