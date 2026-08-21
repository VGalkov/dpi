package ru.galkov.llm;

import ru.galkov.util.LocaleUtil;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public class HttpAnomalyDetector extends AbstractAnomalyDetector<HttpQueryRecord> {

    private static final int DEFAULT_MAX_QUEUE_SIZE = 10_000;
    private static final int DEFAULT_BODY_PREVIEW_LENGTH = 500;
    private static final long DEFAULT_MIN_LLM_INTERVAL_MILLIS = 5_000L;
    private final boolean inspectBody;
    private final int maxQueueSize;
    private final int bodyPreviewLength;
    private final long minLlmIntervalMillis;
    private final String promptTemplate;
    private final BlockingQueue<HttpQueryRecord> queue;
    private volatile long lastLlmRequestTime;

    public HttpAnomalyDetector() {
        super("http.anomaly-detector");

        this.inspectBody = getConfigBoolean("http.anomaly-detector.inspect-body");

        this.maxQueueSize = Math.max(
                1, getConfigInt("http.anomaly-detector.max-queue-size", DEFAULT_MAX_QUEUE_SIZE)
        );

        this.bodyPreviewLength = Math.max(
                0,
                getConfigInt("http.anomaly-detector.body-preview-length", DEFAULT_BODY_PREVIEW_LENGTH)
        );

        this.minLlmIntervalMillis = Math.max(
                0L,
                getConfigInt(
                        "http.anomaly-detector.min-llm-interval-millis",
                        (int) DEFAULT_MIN_LLM_INTERVAL_MILLIS
                )
        );

        this.queue = new LinkedBlockingQueue<>(maxQueueSize);
        this.promptTemplate = llmClient.loadPromptTemplate("prompts/http_anomaly_prompt.txt");
        logger.info(
                LocaleUtil.getString("http_anomaly_detector_initialized"),
                enabled,
                getConfigString("http.anomaly-detector.llm-studio.model"),
                getConfigString("http.anomaly-detector.llm-studio.url"),
                processedTtlMillis / 1000,
                inspectBody
        );
    }

    @Override
    protected String getConfigPrefix() {
        return "http.anomaly-detector";
    }

    @Override
    public void record(HttpQueryRecord record) {
        if (!enabled || !running || record == null) {
            return;
        }

        if (isBlockedByBlacklist(record.getHost(), record.getClientIp())) {
            logger.debug("Skipping blacklisted host={} or clientIp={}", record.getHost(), record.getClientIp());
            return;
        }

        if (!queue.offer(record)) {
            logger.warn(
                    "HTTP anomaly queue is full, dropping request: client={}, host={}, path={}",
                    record.getClientIp(),
                    record.getHost(),
                    record.getPath()
            );
            return;
        }

        logger.debug(
                LocaleUtil.getString("http_anomaly_detector_record_added"),
                record.getClientIp(),
                record.getHost(),
                record.getMethod()
        );
    }

    @Override
    protected void processQueue() {
        while (running) {
            try {
                HttpQueryRecord record = queue.poll(1, TimeUnit.SECONDS);
                if (record == null) continue;
                waitForLlmInterval();

                // ✅ Используем общий метод из AbstractAnomalyDetector
                analyzeRecord(record);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error(
                        LocaleUtil.getString("http_anomaly_detector_analysis_error"),
                        e.getMessage(),
                        e
                );
            }
        }

        logger.info(LocaleUtil.getString("http_anomaly_detector_queue_completed"));
    }

    @Override
    protected String buildPrompt(HttpQueryRecord record) {
        String bodyPreview = "";

        if (inspectBody && !record.getBody().isEmpty()) {
            bodyPreview = record.getBody();
            if (bodyPreview.length() > bodyPreviewLength)
                bodyPreview = bodyPreview.substring(0, bodyPreviewLength);
        }

        if (promptTemplate == null || promptTemplate.isBlank()) return "";

        return promptTemplate
                .replace("{clientIp}", promptValue(record.getClientIp(), 128))
                .replace("{method}", promptValue(record.getMethod(), 32))
                .replace("{host}", promptValue(record.getHost(), 253))
                .replace("{port}", String.valueOf(record.getPort()))
                .replace("{path}", promptValue(record.getPath(), 4096))
                .replace("{headers}", promptValue(record.getHeaders(), 8192))
                .replace("{bodyPreview}", promptValue(bodyPreview, bodyPreviewLength))
                .replace("{timestamp}", String.valueOf(record.getTimestamp()))
                .replace("{pathLength}", String.valueOf(record.getPathLength()))
                .replace("{headerLength}", String.valueOf(record.getHeaderLength()))
                .replace("{bodyLength}", String.valueOf(record.getBodyLength()))
                .replace("{https}", String.valueOf(record.isHttps()))
                .replace("{hostIsIp}", String.valueOf(record.isHostIp()))
                .replace("{suspiciousTld}", String.valueOf(record.hasSuspiciousTld()))
                .replace("{pathHasTraversal}", String.valueOf(record.hasPathTraversal()))
                .replace("{pathHasInjectionMarkers}", String.valueOf(record.hasPathInjectionMarkers()))
                .replace("{bodyHasInjectionMarkers}", String.valueOf(record.hasBodyInjectionMarkers()))
                .replace("{suspiciousUserAgent}", String.valueOf(record.hasSuspiciousUserAgent()));
    }

    @Override
    protected void logAnomaly(HttpQueryRecord record, AnalysisResult result) {
        logger.info(
                "HTTP anomaly detected: client={}, method={}, host={}, path={}, confidence={}, "
                        + "reason={}, actions={}",
                record.getClientIp(),
                record.getMethod(),
                record.getHost(),
                record.getPath(),
                result.confidence(),
                result.reason(),
                result.recommendedActions()
        );
    }

    private void waitForLlmInterval() throws InterruptedException {
        while (running) {
            long elapsed = System.currentTimeMillis() - lastLlmRequestTime;
            long remaining = minLlmIntervalMillis - elapsed;
            if (remaining <= 0) return;
            Thread.sleep(Math.min(remaining, 100L));
        }
    }

    public void recordRequest(
            String clientIp,
            String method,
            String host,
            int port,
            String path,
            String headers,
            String body
    ) {
        record(
                new HttpQueryRecord(
                        clientIp,
                        method,
                        host,
                        port,
                        path,
                        headers,
                        body,
                        System.currentTimeMillis()
                )
        );
    }
}