package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
/**
 * ✅ Оптимизация п.16: общий абстрактный класс для AnomalyDetector
 */
public abstract class AbstractAnomalyDetector<T> {
    protected static final Logger logger = LoggerFactory.getLogger(AbstractAnomalyDetector.class);

    protected final boolean enabled;
    protected final LlmClient llmClient;
    protected final long processedTtlMillis;
    protected final double trustThreshold;

    protected final ExecutorService executor;
    protected volatile boolean running;

    protected AbstractAnomalyDetector(String configPrefix) {
        this.enabled = getConfigBoolean(configPrefix + ".enabled");
        this.llmClient = new LlmClient(
                getConfigString(configPrefix + ".llm-studio.url"),
                getConfigString(configPrefix + ".llm-studio.model"),
                getConfigInt(configPrefix + ".llm-studio.timeout-seconds"),
                getConfigString(configPrefix + ".llm-studio.api-key")
        );
        double threshold = 0.7;
        try { threshold = Double.parseDouble(getConfigString(configPrefix + ".trust-threshold")); } catch (NumberFormatException ignored) {}
        this.trustThreshold = threshold;
        int ttlSeconds = 3600;
        try { ttlSeconds = getConfigInt(configPrefix + ".processed-ttl-seconds"); } catch (Exception ignored) {}
        this.processedTtlMillis = ttlSeconds * 1000L;
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, getClass().getSimpleName() + "-Thread");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * ✅ Общий метод для запуска
     */
    public void start() {
        if (!enabled) {
            logger.info(LocaleUtil.getString(getConfigPrefix() + "_disabled"));
            return;
        }
        if (running) {
            logger.warn(LocaleUtil.getString(getConfigPrefix() + "_already_running"));
            return;
        }
        running = true;
        executor.submit(this::processQueue);
        logger.info(LocaleUtil.getString(getConfigPrefix() + "_started"), getConfigString(getConfigPrefix().replace("_", ".") + ".llm-studio.model"));
    }

    /**
     * ✅ Общий метод для остановки
     */
    public void stop() {
        if (!running) return;
        running = false;
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
        logger.info(LocaleUtil.getString(getConfigPrefix() + "_stopped"));
    }

    /**
     * ✅ Общий метод для проверки статуса
     */
    public boolean isEnabled() {
        return enabled && running;
    }

    /**
     * ✅ Абстрактный метод для обработки очереди (реализуется в наследниках)
     */
    protected abstract void processQueue();

    /**
     * ✅ Абстрактный метод для добавления записи в очередь (реализуется в наследниках)
     */
    public abstract void record(T record);

    /**
     * ✅ Общий метод для анализа записи через LLM
     */
    protected AnalysisResult analyzeWithLlm(String prompt) {
        try {
            String response = llmClient.sendRequest(prompt);
            if (response == null || response.isEmpty()) {
                logger.warn(LocaleUtil.getString(getConfigPrefix() + "_empty_response"));
                return null;
            }
            return llmClient.parseResponse(response);
        } catch (Exception e) {
            logger.error(LocaleUtil.getString(getConfigPrefix() + "_analysis_error"), e.getMessage(), e);
            return null;
        }
    }

    /**
     * ✅ Абстрактный метод для получения префикса конфига
     */
    protected abstract String getConfigPrefix();

    /**
     * ✅ Вспомогательные методы для получения конфига
     */
    protected static String getConfigString(String key) {
        try {
            return ru.galkov.Main.getConfig().get(key);
        } catch (Exception e) {
            return "";
        }
    }

    protected static int getConfigInt(String key) {
        try {
            return ru.galkov.Main.getConfig().getInt(key);
        } catch (Exception e) {
            return 0;
        }
    }

    protected static boolean getConfigBoolean(String key) {
        try {
            return ru.galkov.Main.getConfig().getBoolean(key);
        } catch (Exception e) {
            return false;
        }
    }
}