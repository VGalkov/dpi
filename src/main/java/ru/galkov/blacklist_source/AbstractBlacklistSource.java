package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.BlacklistRule;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public abstract class AbstractBlacklistSource implements BlacklistSource {
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    protected List<BlacklistRule> loadFromStream(InputStream input, String sourceName) throws IOException {
        List<BlacklistRule> rules = new ArrayList<>(1000);
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                BlacklistRule rule = parseLine(line, sourceName);
                if (rule != null) rules.add(rule);
            }
        }
        return rules;
    }

    protected BlacklistRule parseLine(String line, String sourceName) {
        if (line == null) return null;
        String value = line.trim();
        if (value.isEmpty() || value.startsWith("#") || value.startsWith("!")) return null;

        int commentIndex = value.indexOf('#');
        if (commentIndex >= 0) value = value.substring(0, commentIndex).trim();

        if (value.isEmpty()) return null;

        return new BlacklistRule(BlacklistRule.RuleType.DOMAIN, value, sourceName, null, null);
    }
}