package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.*;

import static ru.galkov.Main.getConfig;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class HttpAnomalyDetector {

    private static final Logger logger = LoggerFactory.getLogger(HttpAnomalyDetector.class);

    private final boolean enabled;
    private final String llmUrl;
    private final String model;
    private final Duration timeout;
    private final String apiKey;
    private final double trustThreshold;
    private final long processedTtlMillis;
    private final boolean inspectBody;

    private final BlockingQueue<HttpQueryRecord> queue = new LinkedBlockingQueue<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "HttpAnomalyDetector-Thread");
        t.setDaemon(true);
        return t;
    });

    private volatile boolean running;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public HttpAnomalyDetector() {
        this.enabled = getConfig().getBoolean("http.anomaly-detector.enabled");
        this.llmUrl = getConfig().get("http.anomaly-detector.llm-studio.url");
        this.model = getConfig().get("http.anomaly-detector.llm-studio.model");
        this.timeout = Duration.ofSeconds(getConfig().getInt("http.anomaly-detector.llm-studio.timeout-seconds"));
        this.apiKey = getConfig().get("http.anomaly-detector.llm-studio.api-key");
        double threshold = 0.7;
        try { threshold = Double.parseDouble(getConfig().get("http.anomaly-detector.trust-threshold")); } catch (NumberFormatException ignored) {}
        this.trustThreshold = threshold;
        int ttlSeconds = 3600;
        try { ttlSeconds = Integer.parseInt(getConfig().get("http.anomaly-detector.processed-ttl-seconds")); } catch (Exception ignored) {}
        this.processedTtlMillis = ttlSeconds * 1000L;
        this.inspectBody = getConfig().getBoolean("http.anomaly-detector.inspect-body");
        logger.info(LocaleUtil.getString("http_anomaly_detector_initialized"), enabled, model, llmUrl, processedTtlMillis / 1000, inspectBody);
    }

    public void processQueue() {
        while (running) {
            try {
                HttpQueryRecord record = queue.poll(1, TimeUnit.SECONDS);
                if (record == null) continue;
                analyzeRecord(record);
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            catch (Exception e) { logger.error(LocaleUtil.getString("http_anomaly_detector_analysis_error"), e.getMessage(), e); }
        }
    }


    public void start() {
        if (!enabled) {
            logger.info(LocaleUtil.getString("http_anomaly_detector_disabled"));
            return;
        }

        if (running) {
            logger.warn(LocaleUtil.getString("http_anomaly_detector_already_running"));
            return;
        }

        running = true;
        executor.submit(this::processQueue);
        logger.info(LocaleUtil.getString("http_anomaly_detector_started"), model);
    }

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
        logger.info(LocaleUtil.getString("http_anomaly_detector_stopped"));
    }

    public boolean isEnabled() {
        return enabled && running;
    }

    public void recordRequest(String clientIp, String method, String host, int port, String path,
                              String headers, String body) {
        if (!enabled || !running) return;

        try {
            HttpQueryRecord record = new HttpQueryRecord(clientIp, method, host, port, path,
                    headers, body, System.currentTimeMillis());
            queue.offer(record);
            logger.debug(LocaleUtil.getString("http_anomaly_detector_record_added"),
                    clientIp, host, method);
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("http_anomaly_detector_queue_add_error"), e.getMessage(), e);
        }
    }

    private void analyzeRecord(HttpQueryRecord record) {
        if (llmUrl == null || llmUrl.isEmpty()) {
            logger.warn(LocaleUtil.getString("http_anomaly_detector_llm_url_not_configured"));
        }

        if (model == null || model.isEmpty()) {
            logger.warn(LocaleUtil.getString("http_anomaly_detector_llm_model_not_configured"));
        }

        try {
            String prompt = buildPrompt(record);

            logger.info(LocaleUtil.getString("http_anomaly_detector_sending_request"), model, llmUrl);
            logger.debug(LocaleUtil.getString("http_anomaly_detector_prompt"), prompt);

            String response = sendToLlm(prompt);

            if (response == null || response.isEmpty()) {
                logger.warn(LocaleUtil.getString("http_anomaly_detector_empty_response"));
            }

            logger.debug(LocaleUtil.getString("http_anomaly_detector_response"), response);
            parseResponse(response);

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

        return loadPromptTemplate("prompts/http_anomaly_prompt.txt")
                .replace("{clientIp}", record.getClientIp())
                .replace("{method}", record.getMethod())
                .replace("{host}", record.getHost())
                .replace("{port}", String.valueOf(record.getPort()))
                .replace("{path}", record.getPath())
                .replace("{headers}", record.getHeaders())
                .replace("{bodyPreview}", bodyPreview);
    }

    private String loadPromptTemplate(String resourceName) {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourceName)) {
            if (is == null) {
                logger.warn("Шаблон промпта не найден: {}", resourceName);
                return "";
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Ошибка загрузки шаблона промпта: {}", resourceName, e);
            return "";
        }
    }

    private String sendToLlm(String prompt) throws IOException, InterruptedException {
        // Экранируем специальные символы для JSON
        String escapedPrompt = prompt
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");

        String jsonBody = String.format(
                "{" +
                        "\"model\": \"%s\"," +
                        "\"messages\": [" +
                        "  {\"role\": \"user\", \"content\": \"%s\"}" +
                        "]," +
                        "\"temperature\": 0.1," +
                        "\"max_tokens\": 500" +
                        "}",
                model,
                escapedPrompt
        );

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(llmUrl))
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody));

        if (apiKey != null && !apiKey.isEmpty())
            builder.header("Authorization", "Bearer " + apiKey);

        HttpRequest request = builder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            logger.warn(LocaleUtil.getString("http_anomaly_detector_llm_status"), response.statusCode());
            return null;
        }

        return response.body();
    }

    private AnalysisResult parseResponse(String responseBody) {
        try {
            int choicesStart = responseBody.indexOf("\"choices\"");
            if (choicesStart < 0) return null;

            int contentStart = responseBody.indexOf("\"content\"", choicesStart);
            if (contentStart < 0) return null;

            int colonPos = responseBody.indexOf(":", contentStart);
            if (colonPos < 0) return null;

            int quoteStart = responseBody.indexOf("\"", colonPos + 1);
            if (quoteStart < 0) return null;

            int quoteEnd = findMatchingQuote(responseBody, quoteStart + 1);
            if (quoteEnd < 0) return null;

            String content = responseBody.substring(quoteStart + 1, quoteEnd)
                    .replace("\\\"", "\"")
                    .replace("\\n", "\n");

            logger.debug(LocaleUtil.getString("http_anomaly_detector_parsed_json"), content);

            boolean isSuspicious = content.contains("\"isSuspicious\":true");
            double confidence = extractConfidence(content);
            String reason = extractField(content, "reason");
            logger.info(LocaleUtil.getString("http_anomaly_detector_analysis_result"),
                    isSuspicious, confidence, reason);
            return new AnalysisResult(isSuspicious, confidence, reason, null);
        } catch (Exception e) {
            logger.debug(LocaleUtil.getString("http_anomaly_detector_parse_error"), e.getMessage());
            return null;
        }
    }

    private int findMatchingQuote(String json, int start) {
        boolean escaped = false;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') return i;
        }
        return -1;
    }

    private double extractConfidence(String content) {
        try {
            int confStart = content.indexOf("\"confidence\":");
            if (confStart < 0) return 0.0;

            int colonPos = content.indexOf(":", confStart);
            if (colonPos < 0) return 0.0;

            int endPos = content.indexOf(",", colonPos);
            if (endPos < 0) endPos = content.indexOf("}", colonPos);
            if (endPos < 0) return 0.0;

            String confStr = content.substring(colonPos + 1, endPos).trim();
            return Double.parseDouble(confStr);

        } catch (Exception e) {
            return 0.0;
        }
    }

    private String extractField(String content, String fieldName) {
        try {
            int fieldStart = content.indexOf("\"" + fieldName + "\"");
            if (fieldStart < 0) return "";

            int colonPos = content.indexOf(":", fieldStart);
            if (colonPos < 0) return "";

            int quoteStart = content.indexOf("\"", colonPos + 1);
            if (quoteStart < 0) return "";

            int quoteEnd = findMatchingQuote(content, quoteStart + 1);
            if (quoteEnd < 0) return "";

            return content.substring(quoteStart + 1, quoteEnd);

        } catch (Exception e) {
            return "";
        }
    }
}