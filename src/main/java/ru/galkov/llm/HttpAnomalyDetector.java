package ru.galkov.llm;

import ru.galkov.util.LocaleUtil;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * HTTP-детектор аномалий на базе LlmAnomalyDetector.
 */
public class HttpAnomalyDetector extends LlmAnomalyDetector<HttpQueryRecord> {
    private static final int DEFAULT_MAX_QUEUE_SIZE = 10_000;
    private static final int DEFAULT_BODY_PREVIEW_LENGTH = 500;
    private static final long DEFAULT_MIN_LLM_INTERVAL_MILLIS = 5_000L;
    private final boolean inspectBody;
    private final int maxQueueSize;
    private final int bodyPreviewLength;
    private final long minLlmIntervalMillis;
    private final BlockingQueue<HttpQueryRecord> queue;
    private volatile long lastLlmRequestTime;

    public HttpAnomalyDetector() {
        super(new HttpAnomalyStrategy("http.anomaly-detector",
                        getConfigBoolean("http.anomaly-detector.inspect-body"),
                        getConfigInt("http.anomaly-detector.body-preview-length", DEFAULT_BODY_PREVIEW_LENGTH)),
                "http.anomaly-detector");
        this.inspectBody = getConfigBoolean("http.anomaly-detector.inspect-body");
        this.maxQueueSize = Math.max(1, getConfigInt("http.anomaly-detector.max-queue-size", DEFAULT_MAX_QUEUE_SIZE));
        this.bodyPreviewLength = Math.max(0, getConfigInt("http.anomaly-detector.body-preview-length", DEFAULT_BODY_PREVIEW_LENGTH));
        this.minLlmIntervalMillis = Math.max(0L, getConfigInt("http.anomaly-detector.min-llm-interval-millis", (int) DEFAULT_MIN_LLM_INTERVAL_MILLIS));
        this.queue = new LinkedBlockingQueue<>(maxQueueSize);
    }

    @Override
    protected void processQueue() {
        while (running) {
            try {
                HttpQueryRecord record = queue.poll(1, TimeUnit.SECONDS);
                if (record == null) continue;
                waitForLlmInterval();
                analyzeRecord(record);
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            catch (Exception e) {
                logger.error(LocaleUtil.getString("http_anomaly_detector_analysis_error"), e.getMessage(), e);
            }
        }
        logger.debug(LocaleUtil.getString("http_anomaly_detector_queue_completed"));
    }

    @Override
    public void record(HttpQueryRecord record) {
        if (!enabled || !running || record == null) return;
        if (isBlockedByBlacklist(record.getHost(), record.getClientIp())) {
            logger.debug("Skipping blacklisted host={} or clientIp={}", record.getHost(), record.getClientIp());
            return;
        }
        if (!queue.offer(record)) {
            logger.warn("HTTP anomaly queue is full, dropping request: client={}, host={}, path={}",
                    record.getClientIp(), record.getHost(), record.getPath());
            return;
        }
        logger.debug(LocaleUtil.getString("http_anomaly_detector_record_added"),
                record.getClientIp(), record.getHost(), record.getMethod());
    }

    private void waitForLlmInterval() throws InterruptedException {
        while (running) {
            long elapsed = System.currentTimeMillis() - lastLlmRequestTime;
            long remaining = minLlmIntervalMillis - elapsed;
            if (remaining <= 0) return;
            Thread.sleep(Math.min(remaining, 100L));
        }
    }

    public void recordRequest(String clientIp, String method, String host, int port,
                              String path, String headers, String body) {
        record(new HttpQueryRecord(clientIp, method, host, port, path, headers, body, System.currentTimeMillis()));
    }
}