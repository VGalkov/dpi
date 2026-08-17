package ru.galkov.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class LocaleUtil {
    private static ResourceBundle messages;
    private static String currentPrefix;

    public static void reload() {
        // Читаем locale.prefix из application.properties вручную
        String prefix = loadLocalePrefix();

        System.out.println("DEBUG: locale.prefix from properties = " + prefix);

        // Очищаем кэш ResourceBundle
        ResourceBundle.clearCache();

        try {
            currentPrefix = prefix;
            messages = ResourceBundle.getBundle("locale/messages", new Locale(prefix, ""), new Utf8Control());

            System.out.println("DEBUG: Loaded bundle: " + messages);
        } catch (Exception e) {
            messages = null;
            System.out.println("DEBUG: Failed to load bundle: " + e.getMessage());
        }
    }

    // Читаем locale.prefix из application.properties
    private static String loadLocalePrefix() {
        Properties props = new Properties();

        // Пытаемся загрузить из classpath
        URL resource = LocaleUtil.class.getClassLoader().getResource("application.properties");
        if (resource != null) {
            try (InputStream is = resource.openStream()) {
                props.load(is);
                String prefix = props.getProperty("locale.prefix");
                if (prefix != null && !prefix.isEmpty()) {
                    return prefix.trim();
                }
            } catch (Exception e) {
                // Игнорируем, используем дефолт
            }
        }

        // Дефолт
        return "ru";
    }

    public static String getString(String key) {
        if (messages == null) {
            reload();
            if (messages == null) {
                return key;
            }
        }
        try {
            return messages.getString(key);
        } catch (Exception e) {
            return key;
        }
    }

    public static String getString(String key, Object... args) {
        if (messages == null) {
            reload();
            if (messages == null) {
                return key;
            }
        }
        try {
            return String.format(messages.getString(key), args);
        } catch (Exception e) {
            return key;
        }
    }

    // Кастомный контроллер для UTF-8
    private static class Utf8Control extends ResourceBundle.Control {
        @Override
        public ResourceBundle newBundle(String baseName, Locale locale, String format,
                                        ClassLoader loader, boolean reload)
                throws IllegalAccessException, InstantiationException, IOException {
            String bundleName = toBundleName(baseName, locale);
            String resourceName = toResourceName(bundleName, "properties");
            URL resource = loader.getResource(resourceName);

            if (resource != null) {
                URLConnection connection = resource.openConnection();
                connection.setUseCaches(!reload);

                try (InputStream stream = connection.getInputStream();
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