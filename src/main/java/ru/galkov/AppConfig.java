
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

    // Путь по умолчанию. Можно переопределить через -Dconfig.path=/path/to/config.properties
    private static final String DEFAULT_PATH = "application.properties";

    private Properties props;

    // Singleton
    private AppConfig(String path) throws IOException {
        this.props = load(path);
    }

    private static class Holder {
        private static AppConfig INSTANCE;
    }

    public static synchronized AppConfig getInstance() throws IOException {
        // Проверяем, существует ли файл по указанному пути (или по умолчанию)
        String path = System.getProperty("config.path", DEFAULT_PATH);

        if (Holder.INSTANCE == null) {
            logger.info("Попытка загрузки конфигурации из: {}", path);
            Holder.INSTANCE = new AppConfig(path);
        }
        return Holder.INSTANCE;
    }

    public static AppConfig get() {
        if (Holder.INSTANCE == null) {
            throw new IllegalStateException("AppConfig ещё не инициализирован. Вызовите getInstance() в main.");
        }
        return Holder.INSTANCE;
    }

    public synchronized void reload() throws IOException {
        getInstance().props = getInstance().load(System.getProperty("config.path", DEFAULT_PATH));
    }

    /* -----------------------------------------------------------------
     * ЛОГИКА ЗАГРУЗКИ: Диск -> JAR
     * ----------------------------------------------------------------- */
    private synchronized Properties load(String path) throws IOException {
        Properties raw = new Properties();
        InputStream inputStream;
        File configFile = new File(path);

        try {
            // 1. ПРИОРИТЕТ: Пробуем прочитать файл с диска (рядом с JAR)
            if (configFile.exists() && configFile.isFile()) {
                logger.info("✅ Конфиг найден на диске: {}", configFile.getAbsolutePath());
                try (FileInputStream fis = new FileInputStream(configFile)) {
                    raw.load(fis);
                }
            }
            // 2. ФОЛБЭК: Если файла нет на диске, пробуем найти внутри JAR
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

            // Если файл пустой или не загрузился
            if (raw.isEmpty()) {
                throw new IOException("⚠️ Конфиг не найден на диске или внутри JAR!");
            }

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

    /* -----------------------------------------------------------------
     * Публичный API (без изменений, только исправлено название метода внизу)
     * ----------------------------------------------------------------- */

    public String get(String key) {
        String val = props.getProperty(key);
        if (val == null) {
            throw new IllegalStateException("Ключ '" + key + "' не найден в application.properties");
        }
        return val;
    }

    public String getString(String key) {
        return get(key); // Делегируем основному методу
    }

    public List<String> getList(String key) {
        String raw = get(key);
        if (raw.trim().isEmpty()) return Collections.emptyList();

        String[] parts = raw.split("\\s*,\\s*");
        return Arrays.asList(parts);
    }

    // Исправлена опечатка в названии метода (было getProterties)
    public Properties getProperties() {
        return props;
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