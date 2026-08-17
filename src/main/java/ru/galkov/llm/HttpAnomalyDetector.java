package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LogFields;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.*;

import static ru.galkov.Main.getConfig;

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

    private final Map<String, Long> processedHosts = new ConcurrentHashMap<>();
    private final Map<String, Long> processedClients = new ConcurrentHashMap<>();

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

        String thresholdStr = getConfig().get("http.anomaly-detector.trust-threshold");
        double threshold = 0.7;
        try {
            threshold = Double.parseDouble(thresholdStr);
        } catch (NumberFormatException e) {
            // оставить 0.7
        }
        this.trustThreshold = threshold;

        int ttlSeconds = 3600;
        try {
            String ttlStr = getConfig().get("http.anomaly-detector.processed-ttl-seconds");
            if (ttlStr != null && !ttlStr.isEmpty()) {
                ttlSeconds = Integer.parseInt(ttlStr);
            }
        } catch (NumberFormatException e) {
            logger.warn("Некорректный http.anomaly-detector.processed-ttl-seconds, использую 3600");
        }
        this.processedTtlMillis = ttlSeconds * 1000L;

        this.inspectBody = getConfig().getBoolean("http.anomaly-detector.inspect-body");

        logger.info("HttpAnomalyDetector инициализирован: enabled={}, model={}, url={}, ttl={}s, inspectBody={}",
                enabled, model, llmUrl, processedTtlMillis / 1000, inspectBody);
    }

    private boolean isProcessed(String host, String clientIp) {
        return processedHosts.containsKey(host) || processedClients.containsKey(clientIp);
    }

    private void markProcessed(String host, String clientIp) {
        long now = System.currentTimeMillis();
        processedHosts.put(host, now);
        processedClients.put(clientIp, now);
    }

    private void cleanupProcessed() {
        long now = System.currentTimeMillis();
        long expiryTime = now - processedTtlMillis;

        int removedHosts = 0;
        int removedClients = 0;

        for (Map.Entry<String, Long> entry : processedHosts.entrySet()) {
            if (entry.getValue() < expiryTime) {
                processedHosts.remove(entry.getKey());
                removedHosts++;
            }
        }

        for (Map.Entry<String, Long> entry : processedClients.entrySet()) {
            if (entry.getValue() < expiryTime) {
                processedClients.remove(entry.getKey());
                removedClients++;
            }
        }

        if (removedHosts > 0 || removedClients > 0) {
            logger.info("HttpAnomalyDetector: очистка устаревших записей: hosts={}, clients={}, ttl={}s",
                    removedHosts, removedClients, processedTtlMillis / 1000);
        }
    }

    public void start() {
        if (!enabled) {
            logger.info("HttpAnomalyDetector отключён в конфиге");
            return;
        }

        if (running) {
            logger.warn("HttpAnomalyDetector уже запущен");
            return;
        }

        running = true;
        executor.submit(this::processQueue);
        logger.info("HttpAnomalyDetector запущен, модель={}", model);
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
        logger.info("HttpAnomalyDetector остановлен");
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

            queue.removeIf(r -> r.getHost().equals(host));

            queue.offer(record);
            logger.debug("HttpAnomalyDetector: запись добавлена в очередь: client={}, host={}, method={}",
                    clientIp, host, method);
        } catch (Exception e) {
            logger.debug("Ошибка добавления записи в очередь: {}", e.getMessage());
        }
    }

    private void processQueue() {
        long lastCleanupTime = System.currentTimeMillis();
        long cleanupIntervalMillis = 10000;
        long lastLlmRequestTime = 0;
        long llmRequestIntervalMillis = 120000;

        while (running) {
            try {
                long now = System.currentTimeMillis();

                if (now - lastLlmRequestTime < llmRequestIntervalMillis) {
                    Thread.sleep(100);
                    continue;
                }

                if (now - lastCleanupTime > cleanupIntervalMillis) {
                    cleanupProcessed();
                    lastCleanupTime = now;
                    logger.info("HttpAnomalyDetector: очистка processedDomains/processedClients выполнена, ttl={}s",
                            processedTtlMillis / 1000);
                }

                HttpQueryRecord record = queue.poll(1, TimeUnit.SECONDS);
                if (record == null) continue;
                String host = record.getHost();

                if (isProcessed(host, record.getClientIp())) {
                    logger.debug("HttpAnomalyDetector: пропуск записи (уже обработано): client={}, host={}",
                            record.getClientIp(), host);
                    continue;
                }

                markProcessed(host, record.getClientIp());

                logger.info("HttpAnomalyDetector: анализ записи: client={}, host={}, method={}, path={}",
                        record.getClientIp(), host, record.getMethod(), record.getPath());

                HttpAnalysisResult result = analyzeRecord(record);
                lastLlmRequestTime = System.currentTimeMillis();

                if (result != null && result.isSuspicious() && result.getConfidence() >= trustThreshold) {
                    logger.info("{} {} {} {} {} {} {}",
                            LogFields.kv("event", "HTTP_ANOMALY_DETECTED"),
                            LogFields.kv("client", record.getClientIp()),
                            LogFields.kv("host", host),
                            LogFields.kv("method", record.getMethod()),
                            LogFields.kv("confidence", result.getConfidence()),
                            LogFields.kv("reason", result.getReason()),
                            LogFields.kv("timestamp", record.getTimestamp()));
                } else if (result != null) {
                    logger.info("HttpAnomalyDetector: запрос не подозрителен: client={}, host={}, method={}, confidence={}, reason={}",
                            record.getClientIp(), host, record.getMethod(), result.getConfidence(), result.getReason());
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Ошибка обработки записи: {}", e.getMessage());
            }
        }

        logger.info("HttpAnomalyDetector завершил обработку очереди");
    }

    private HttpAnalysisResult analyzeRecord(HttpQueryRecord record) {
        if (llmUrl == null || llmUrl.isEmpty()) {
            logger.warn("LLM Studio URL не настроен");
            return null;
        }

        if (model == null || model.isEmpty()) {
            logger.warn("LLM Studio model не настроен");
            return null;
        }

        try {
            String prompt = buildPrompt(record);

            logger.info("HttpAnomalyDetector: отправка запроса в LLM Studio: model={}, url={}", model, llmUrl);
            logger.debug("HttpAnomalyDetector: промпт: {}", prompt);

            String response = sendToLlm(prompt);

            if (response == null || response.isEmpty()) {
                logger.warn("HttpAnomalyDetector: пустой ответ от LLM Studio");
                return null;
            }

            logger.debug("HttpAnomalyDetector: ответ LLM Studio: {}", response);

            return parseResponse(response);

        } catch (Exception e) {
            logger.error("Ошибка анализа записи: {}", e.getMessage(), e);
            return null;
        }
    }

    private String buildPrompt(HttpQueryRecord record) {
        String bodyPreview = "";
        if (inspectBody && record.getBody() != null && !record.getBody().isEmpty()) {
            bodyPreview = record.getBody().length() > 500 ?
                    record.getBody().substring(0, 500) + "..." : record.getBody();
        }

        return String.format(
                "Ты — система безопасности, анализирующая HTTP-трафик на аномалии.\n\n" +
                        "Проанализируй HTTP-запрос:\n" +
                        "- Client IP: %s\n" +
                        "- Method: %s\n" +
                        "- Host: %s\n" +
                        "- Port: %d\n" +
                        "- Path: %s\n" +
                        "- Headers:\n%s\n" +
                        "- Body (first 500 chars): %s\n\n" +
                        "Критерии подозрительности:\n" +
                        "1. SQL Injection: SELECT, UNION, DROP, INSERT, UPDATE, DELETE, OR 1=1 → confidence=0.9\n" +
                        "2. XSS: <script>, javascript:, onerror=, onload= → confidence=0.8\n" +
                        "3. Path Traversal: ../, ..\\\\, 2e2e2f → confidence=0.8\n" +
                        "4. Command Injection: ;, |, &, $(), 0a, 0d → confidence=0.7\n" +
                        "5. Suspicious User-Agent: curl, wget, python, nikto, sqlmap, nmap → confidence=0.6\n" +
                        "6. Suspicious Host: IP-адрес или необычный TLD (.xyz, .top, .tk) → confidence=0.5\n\n" +
                        "Ответь ТОЛЬКО в формате JSON:\n" +
                        "{\n" +
                        "  \"isSuspicious\": true/false,\n" +
                        "  \"confidence\": 0.0-1.0,\n" +
                        "  \"reason\": \"краткое объяснение\",\n" +
                        "  \"recommendedActions\": [\"BLOCK_REQUEST\"/\"LOG_ONLY\"/\"NONE\"]\n" +
                        "}",
                record.getClientIp(),
                record.getMethod(),
                record.getHost(),
                record.getPort(),
                record.getPath(),
                record.getHeaders(),
                bodyPreview
        );
    }

    private String sendToLlm(String prompt) throws IOException, InterruptedException {
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
                prompt.replace("\"", "\\\"").replace("\n", "\\n")
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
            logger.warn("LLM Studio вернул статус: {}", response.statusCode());
            return null;
        }

        return response.body();
    }

    private HttpAnalysisResult parseResponse(String responseBody) {
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

            logger.debug("HttpAnomalyDetector: распарсенный JSON от LLM: {}", content);

            boolean isSuspicious = content.contains("\"isSuspicious\":true");
            double confidence = extractConfidence(content);
            String reason = extractField(content, "reason");
            logger.info("HttpAnomalyDetector: результат анализа: isSuspicious={}, confidence={}, reason={}",
                    isSuspicious, confidence, reason);
            return new HttpAnalysisResult(isSuspicious, confidence, reason, null);
        } catch (Exception e) {
            logger.debug("Ошибка парсинга ответа LLM: {}", e.getMessage());
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