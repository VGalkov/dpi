package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class HttpAnomalyDetector extends AbstractAnomalyDetector<HttpQueryRecord> {
    private static final Logger logger = LoggerFactory.getLogger(HttpAnomalyDetector.class);

    private final boolean inspectBody;
    private final BlockingQueue<HttpQueryRecord> queue = new LinkedBlockingQueue<>();

    public HttpAnomalyDetector() {
        super("http.anomaly-detector");
        this.inspectBody = getConfigBoolean("http.anomaly-detector.inspect-body");
        logger.info(LocaleUtil.getString("http_anomaly_detector_initialized"), enabled,
                getConfigString("http.anomaly-detector.llm-studio.model"),
                getConfigString("http.anomaly-detector.llm-studio.url"),
                processedTtlMillis / 1000, inspectBody);
    }

    @Override
    protected String getConfigPrefix() {
        return "http_anomaly_detector";
    }

    @Override
    public void record(HttpQueryRecord record) {
        if (!enabled || !running || record == null) return;

        try {
            queue.offer(record);
            logger.debug(LocaleUtil.getString("http_anomaly_detector_record_added"),
                    record.getClientIp(), record.getHost(), record.getMethod());
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("http_anomaly_detector_queue_add_error"), e.getMessage(), e);
        }
    }

    @Override
    protected void processQueue() {
        while (running) {
            try {
                HttpQueryRecord record = queue.poll(1, TimeUnit.SECONDS);
                if (record == null) continue;
                analyzeRecord(record);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error(LocaleUtil.getString("http_anomaly_detector_analysis_error"), e.getMessage(), e);
            }
        }
    }

    private void analyzeRecord(HttpQueryRecord record) {
        try {
            String prompt = buildPrompt(record);
            analyzeWithLlm(prompt);
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("http_anomaly_detector_analysis_error"), e.getMessage(), e);
        }
    }

    private String buildPrompt(HttpQueryRecord record) {
        String bodyPreview = "";
        if (inspectBody && record.getBody() != null && !record.getBody().isEmpty()) {
            bodyPreview = record.getBody().length() > 500 ?
                    record.getBody().substring(0, 500) + "..." : record.getBody();
        }

        return llmClient.loadPromptTemplate("prompts/http_anomaly_prompt.txt")
                .replace("{clientIp}", record.getClientIp())
                .replace("{method}", record.getMethod())
                .replace("{host}", record.getHost())
                .replace("{port}", String.valueOf(record.getPort()))
                .replace("{path}", record.getPath())
                .replace("{headers}", record.getHeaders())
                .replace("{bodyPreview}", bodyPreview);
    }

    // ✅ Метод для обратной совместимости
    public void recordRequest(String clientIp, String method, String host, int port, String path,
                              String headers, String body) {
        record(new HttpQueryRecord(clientIp, method, host, port, path, headers, body, System.currentTimeMillis()));
    }
}