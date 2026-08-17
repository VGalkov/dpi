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
 * Galkov V A [s0506777@yandex.ru](mailto:s0506777@yandex.ru)
 */
public final class AppConfig {
    private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);
    private static final String DEFAULT_PATH = "application.properties";
    private final Properties props;

    private AppConfig(String path) throws IOException {
        this.props = load(path);
    }

    private static class Holder {
        private static AppConfig INSTANCE;
    }

    public static synchronized AppConfig getInstance() throws IOException {
        String path = System.getProperty("config.path", DEFAULT_PATH);

        if (Holder.INSTANCE == null) {
            LocaleUtil.reload();
            String testKey = LocaleUtil.getString("config_attempt_load");
            logger.debug("DEBUG: Loaded locale test: {}", testKey);

            logger.info(testKey, path);
            Holder.INSTANCE = new AppConfig(path);
        }
        return Holder.INSTANCE;
    }

    private synchronized Properties load(String path) throws IOException {
        Properties raw = new Properties();
        InputStream inputStream;
        File configFile = new File(path);

        try {
            if (configFile.exists() && configFile.isFile()) {
                logger.info(LocaleUtil.getString("config_found_disk"), configFile.getAbsolutePath());
                try (FileInputStream fis = new FileInputStream(configFile)) {
                    raw.load(fis);
                }
            }
            else {
                logger.warn(LocaleUtil.getString("config_not_found_disk"), path);
                URL resourceUrl = AppConfig.class.getResource("/application.properties");

                if (resourceUrl != null) {
                    logger.info(LocaleUtil.getString("config_found_jar"));
                    inputStream = resourceUrl.openStream();
                    try {
                        raw.load(inputStream);
                    } finally {
                        if (inputStream != null) inputStream.close();
                    }
                } else {
                    throw new IllegalStateException(
                            LocaleUtil.getString("config_critical_not_found")
                    );
                }
            }

            if (raw.isEmpty())
                throw new IOException(LocaleUtil.getString("config_empty"));

        } catch (IOException e) {
            logger.error(LocaleUtil.getString("config_load_error"), e);
            throw e;
        }

        // Разворачиваем подстановки ${...}
        Properties expanded = new Properties();
        for (String key : raw.stringPropertyNames()) {
            String value = raw.getProperty(key).trim();
            expanded.setProperty(key, resolveValue(value, raw));
        }

        return expanded;
    }

    /**
     * Рекурсивное разрешение всех ${…} в строке.
     */
    private String resolveValue(String value, Properties raw) {

        while (value.contains("${")) {
            int start = value.indexOf("${");
            if (start < 0) break;

            int end = value.indexOf('}', start);
            if (end < 0) throw new IllegalArgumentException(LocaleUtil.getString("unpaired_placeholder", value));

            String keyInside = value.substring(start + 2, end).trim();
            String replacement = raw.getProperty(keyInside);

            if (replacement == null) {
                throw new IllegalStateException(
                        LocaleUtil.getString("value_not_found_for_key", keyInside));
            }

            replacement = resolveValue(replacement, raw);
            value = value.substring(0, start) + replacement + value.substring(end + 1);
        }
        return value;
    }

    public String get(String key) {
        String val = props.getProperty(key);
        if (val == null)
            throw new IllegalStateException(LocaleUtil.getString("key_not_found", key));
        return val;
    }

    public List<String> getList(String key) {
        String raw = get(key).trim();
        if (raw.isEmpty())
            return Collections.emptyList();

        String[] parts = raw.split("\\s*,\\s*");
        List<String> result = new ArrayList<String>();

        for (String part : parts) {
            String value = part.trim();

            if (!value.isEmpty() && !result.contains(value))
                result.add(value);
        }

        return Collections.unmodifiableList(result);
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