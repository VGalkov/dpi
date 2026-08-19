package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public final class HttpAnomalyDetector extends AbstractAnomalyDetector<HttpQueryRecord> {
    private static final Logger logger = LoggerFactory.getLogger(HttpAnomalyDetector.class);

    private final boolean inspectBody;
    private final int maxQueueSize;
    private final BlockingQueue<HttpQueryRecord> queue;

    public HttpAnomalyDetector() {
        super("http.anomaly-detector");

        boolean inspectBodyValue;
        try {
            inspectBodyValue = getConfigBoolean("http.anomaly-detector.inspect-body");
        } catch (IllegalStateException e) {
            inspectBodyValue = false;
        }
        this.inspectBody = inspectBodyValue;

        int maxQueueSizeValue;
        try {
            maxQueueSizeValue = getConfigInt("http.anomaly-detector.max-queue-size", 10000);
        } catch (Exception e) {
            maxQueueSizeValue = 10000;
        }
        this.maxQueueSize = maxQueueSizeValue;
        this.queue = new LinkedBlockingQueue<>(this.maxQueueSize);

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

        boolean added = queue.offer(record);
        if (!added) {
            logger.warn("HTTP anomaly queue full (size={}), dropping record for client={}",
                    queue.size(), record.getClientIp());
        } else {
            logger.debug(LocaleUtil.getString("http_anomaly_detector_record_added"),
                    record.getClientIp(), record.getHost(), record.getMethod());
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

        String template = llmClient.loadPromptTemplate("prompts/http_anomaly_prompt.txt");
        return template
                .replace("{clientIp}", escapePlaceholder(record.getClientIp()))
                .replace("{method}", escapePlaceholder(record.getMethod()))
                .replace("{host}", escapePlaceholder(record.getHost()))
                .replace("{port}", String.valueOf(record.getPort()))
                .replace("{path}", escapePlaceholder(record.getPath()))
                .replace("{headers}", escapePlaceholder(record.getHeaders()))
                .replace("{bodyPreview}", escapePlaceholder(bodyPreview));
    }

    private String escapePlaceholder(String value) {
        if (value == null) return "";
        return value.replace("{", "{{").replace("}", "}}");
    }

    public void recordRequest(String clientIp, String method, String host, int port, String path,
                              String headers, String body) {
        record(new HttpQueryRecord(clientIp, method, host, port, path, headers, body, System.currentTimeMillis()));
    }
}