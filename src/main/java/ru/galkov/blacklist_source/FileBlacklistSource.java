package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
/**
 * s0506777@yandex.ru Galkov V.A.
 */
public final class FileBlacklistSource implements BlacklistSource {

    private static final Logger logger = LoggerFactory.getLogger(FileBlacklistSource.class);

    private final File file;

    public FileBlacklistSource(File file) {
        if (file == null)
            throw new IllegalArgumentException("Файл blacklist не может быть null");

        this.file = file;
    }

    @Override
    public List<String> loadRules() throws IOException {

        List<String> rules = new ArrayList<String>();

        try (
                InputStream input = openInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))
        ) {
            String line;

            while ((line = reader.readLine()) != null) {
                String value = normalizeLine(line);
                if (value == null) {
                    continue;
                }
                rules.add(value);
            }

            logger.info("Локальный blacklist загружен: {}, правил {}", file.getPath(), rules.size());
            return rules;
        }
    }

    private InputStream openInputStream() throws IOException {

        if (file.isFile()) {
            logger.info("Blacklist найден на диске: {}", file.getAbsolutePath());
            return new FileInputStream(file);
        }

        String resourceName = file.getPath().replace('\\', '/');

        while (resourceName.startsWith("/")) {
            resourceName = resourceName.substring(1);
        }

        ClassLoader classLoader = FileBlacklistSource.class.getClassLoader();

        URL resource = classLoader.getResource(resourceName);

        if (resource != null) {
            logger.info("Blacklist найден в classpath: {}", resource.toExternalForm());
            return resource.openStream();
        }

        throw new FileNotFoundException("Blacklist не найден на диске или в classpath: " + file.getAbsolutePath()
        );
    }

    private String normalizeLine(String line) {

        if (line == null) {
            return null;
        }

        String value = line.trim();

        if (value.isEmpty() || value.startsWith("#")) {
            return null;
        }


        int commentIndex = value.indexOf('#');

        if (commentIndex >= 0) {
            value = value.substring(0, commentIndex).trim();
        }

        return value.isEmpty() ? null : value;
    }

    @Override
    public String toString() {
        return "FileBlacklistSource{file=" + file.getAbsolutePath() + '}';
    }
}