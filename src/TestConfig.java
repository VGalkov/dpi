package ru.galkov;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class TestConfig {
    private static final String TEST_CONFIG_PATH = "test.properties";
    private final Properties props;

    private TestConfig() {
        this.props = load();
    }

    private static TestConfig getInstance() {
        TestConfig config = new TestConfig();
        return config;
    }

    private Properties load() {
        Properties raw = new Properties();
        try (FileInputStream fis = new FileInputStream(new File(TEST_CONFIG_PATH))) {
            raw.load(fis);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot load test config", e);
        }
        return raw;
    }

    public String get(String key) {
        return props.getProperty(key);
    }

    public boolean containsKey(String key) {
        return props.containsKey(key);
    }
}
