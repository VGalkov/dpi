package ru.galkov.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

public class LocaleUtil {
    private static ResourceBundle messages;

    static {
        try {
            String prefix = System.getProperty("locale.prefix", "ru");
            messages = ResourceBundle.getBundle("locale.messages", new Locale(prefix), new Utf8Control());
        } catch (Exception e) {
            messages = null;
        }
    }

    public static String getString(String key) {
        if (messages == null) {
            return key;
        }
        try {
            return messages.getString(key);
        } catch (Exception e) {
            return key;
        }
    }

    public static String getString(String key, Object... args) {
        if (messages == null) {
            return key;
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
                                        ClassLoader loader, boolean reload) throws  IOException {
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
    }
}