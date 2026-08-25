package ru.galkov;

import org.slfj.Logger;
import org.slfj.LoggerFactory;
import ru.galkov.util.LocaleUtil;
import ru.galkov.AppConfig;
import ru.galkov.TestConfig;

public final class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        // Основная логика приложения
    }

    public static synchronized AppConfig getInstance() throws IOException {
        // Обычная загрузка конфигурации
        return AppConfig.getInstance();
    }

    public static synchronized TestConfig getTestConfigInstance() {
        return TestConfig.getInstance();
    }

    public static void initConfigForTests() {
        // Загружаем тестовую конфигурацию
        TestConfig testConfig = getTestConfigInstance();
        // Устанавливаем тестовые значения
        // Пример: testConfig.setProperty("key", "value");
        // Валидируем конфигурацию
        testConfig.validateConfig();
    }
}
