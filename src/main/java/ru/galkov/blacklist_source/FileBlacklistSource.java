package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.BlacklistRule;
import ru.galkov.util.LocaleUtil;
import ru.galkov.util.LogFields;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class FileBlacklistSource implements BlacklistSource {

    private static final Logger logger = LoggerFactory.getLogger(FileBlacklistSource.class);
    private static final ResourceBundle messages = ResourceBundle.getBundle("locale.messages");

    private final File file;

    public FileBlacklistSource(File file) {
        if (file == null)
            throw new IllegalArgumentException(LocaleUtil.getString("file_blacklist_cannot_be_null"));

        this.file = file;
    }

    @Override
    public List<BlacklistRule> loadRules() throws IOException {
        List<BlacklistRule> rules = new ArrayList<>();

        try (
                InputStream input = openInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))
        ) {
            String line;

            while ((line = reader.readLine()) != null) {
                BlacklistRule rule = parseLine(line);
                if (rule == null)
                    continue;
                rules.add(rule);
            }

            logger.info(LocaleUtil.getString("local_blacklist_loaded"), file.getPath(), rules.size());
            return rules;
        }
    }

    private BlacklistRule parseLine(String line) {
        if (line == null)
            return null;

        String value = line.trim();

        if (value.isEmpty() || value.startsWith("#"))
            return null;

        int commentIndex = value.indexOf('#');

        if (commentIndex >= 0)
            value = value.substring(0, commentIndex).trim();

        if (value.isEmpty())
            return null;

        return new BlacklistRule(
                BlacklistRule.RuleType.DOMAIN,
                value,
                "LocalFile",
                null,
                null
        );
    }

    private InputStream openInputStream() throws IOException {

        if (file.isFile()) {
            logger.info("{} {}",
                    LogFields.kv("event", LocaleUtil.getString("file_source_found")),
                    LogFields.kv("file", file.getAbsolutePath()));
            return new FileInputStream(file);
        }

        String resourceName = file.getPath().replace('\\', '/');

        while (resourceName.startsWith("/")) {
            resourceName = resourceName.substring(1);
        }

        ClassLoader classLoader = FileBlacklistSource.class.getClassLoader();

        URL resource = classLoader.getResource(resourceName);

        if (resource != null) {
            logger.info(LocaleUtil.getString("blacklist_in_classpath"), resource.toExternalForm());
            return resource.openStream();
        }

        throw new FileNotFoundException(LocaleUtil.getString("blacklist_not_found") + file.getAbsolutePath());
    }

    @Override
    public String toString() {
        return "FileBlacklistSource{file=" + file.getAbsolutePath() + '}';
    }
}