package ru.galkov.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class LocaleUtil {
    private static volatile ResourceBundle messages;
    private static final Map<String, String> messagesCache = new ConcurrentHashMap<>(1024);
    private static volatile String currentLocalePrefix = "ru";
    private static final Object loadLock = new Object();

    /**
     * ✅ П.28: Lazy инициализация — грузим только при первом вызове
     */
    public static void reload() {
        String prefix = loadLocalePrefix();

        if (prefix.equals(currentLocalePrefix) && messages != null) {
            return;
        }

        currentLocalePrefix = prefix;
        messagesCache.clear();

        try {
            messages = ResourceBundle.getBundle("locale/messages", new Locale(prefix), new Utf8Control());
        } catch (Exception e) {
            messages = null;
        }
    }

    private static String loadLocalePrefix() {
        Properties props = new Properties();
        URL resource = LocaleUtil.class.getClassLoader().getResource("application.properties");
        if (resource != null) {
            try (InputStream is = resource.openStream()) {
                props.load(is);
                String prefix = props.getProperty("locale.prefix");
                if (prefix != null && !prefix.isEmpty()) return prefix.trim();
            } catch (Exception ignored) {}
        }
        return "ru";
    }

    /**
     * ✅ П.28: Lazy загрузка при первом вызове
     */
    public static String getString(String key) {
        if (messages == null) {
            synchronized (loadLock) {
                if (messages == null) {
                    reload();
                }
            }
        }

        if (messages == null) return key;

        String cached = messagesCache.get(key);
        if (cached != null) return cached;

        try {
            String value = messages.getString(key);
            messagesCache.put(key, value);
            return value;
        } catch (Exception e) {
            return key;
        }
    }

    public static String getString(String key, Object... args) {
        if (messages == null) {
            synchronized (loadLock) {
                if (messages == null) {
                    reload();
                }
            }
        }

        if (messages == null) return key;

        String cacheKey = key + "_" + Arrays.hashCode(args);
        String cached = messagesCache.get(cacheKey);
        if (cached != null) return cached;

        try {
            String value = String.format(messages.getString(key), args);
            messagesCache.put(cacheKey, value);
            return value;
        } catch (Exception e) {
            return key;
        }
    }

    private static class Utf8Control extends ResourceBundle.Control {
        @Override
        public ResourceBundle newBundle(String baseName, Locale locale, String format, ClassLoader loader, boolean reload)
                throws IOException {
            String bundleName = toBundleName(baseName, locale);
            String resourceName = toResourceName(bundleName, "properties");
            URL resource = loader.getResource(resourceName);
            if (resource != null) {
                URLConnection conn = resource.openConnection();
                conn.setUseCaches(!reload);
                try (InputStream stream = conn.getInputStream();
                     InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                    return new PropertyResourceBundle(reader);
                }
            }
            return null;
        }
        @Override
        public List<String> getFormats(String baseName) {
            return Collections.singletonList("properties");
        }
    }
}