
package ru.galkov;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.*;

/**
 * Galkov V A s0506777@yandex.ru
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
            logger.info("Попытка загрузки конфигурации из: {}", path);
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
                logger.info("✅ Конфиг найден на диске: {}", configFile.getAbsolutePath());
                try (FileInputStream fis = new FileInputStream(configFile)) {
                    raw.load(fis);
                }
            }
            else {
                logger.warn("⚠️ Файл '{}' не найден на диске. Пытаемся найти внутри JAR...", path);
                URL resourceUrl = AppConfig.class.getResource("/application.properties");

                if (resourceUrl != null) {
                    logger.info("✅ Конфиг найден внутри JAR.");
                    inputStream = resourceUrl.openStream();
                    try {
                        raw.load(inputStream);
                    } finally {
                        if (inputStream != null) inputStream.close();
                    }
                } else {
                    throw new IllegalStateException(
                            "❌ КРИТИЧЕСКАЯ ОШИБКА: Не удалось найти application.properties ни на диске, ни внутри JAR!\n" +
                                    "   Проверьте, лежит ли файл application.properties рядом с ac.jar или внутри проекта в папке resources."
                    );
                }
            }

            if (raw.isEmpty())
                throw new IOException("⚠️ Конфиг не найден на диске или внутри JAR!");

        } catch (IOException e) {
            logger.error("❌ Ошибка загрузки конфигурации", e);
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
            if (end < 0) throw new IllegalArgumentException("Непарный ${ в значении: '" + value + "'");

            String keyInside = value.substring(start + 2, end).trim();
            String replacement = raw.getProperty(keyInside);

            if (replacement == null) {
                throw new IllegalStateException(
                        "Не найдено значение для ключа '" + keyInside + "' при разрешении '${...}'");
            }

            replacement = resolveValue(replacement, raw);
            value = value.substring(0, start) + replacement + value.substring(end + 1);
        }
        return value;
    }

    public String get(String key) {
        String val = props.getProperty(key);
        if (val == null)
            throw new IllegalStateException("Ключ '" + key + "' не найден в application.properties");
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