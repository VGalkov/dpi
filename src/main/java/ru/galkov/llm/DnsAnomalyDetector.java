package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;
import ru.galkov.util.LogFields;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.*;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class DnsAnomalyDetector {

    private static final Logger logger = LoggerFactory.getLogger(DnsAnomalyDetector.class);

    private final boolean enabled;
    private final String llmUrl;
    private final String model;
    private final Duration timeout;
    private final String apiKey;
    private final double trustThreshold;
    private final long processedTtlMillis;

    private final BlockingQueue<DnsQueryRecord> queue = new LinkedBlockingQueue<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "DnsAnomalyDetector-Thread");
        t.setDaemon(true);
        return t;
    });

    private final Map<String, Long> processedDomains = new ConcurrentHashMap<>();
    private final Map<String, Long> processedClients = new ConcurrentHashMap<>();

    private volatile boolean running;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public DnsAnomalyDetector() {
        this.enabled = getConfig().getBoolean("dns.anomaly-detector.enabled");
        this.llmUrl = getConfig().get("dns.anomaly-detector.llm-studio.url");
        this.model = getConfig().get("dns.anomaly-detector.llm-studio.model");
        this.timeout = Duration.ofSeconds(getConfig().getInt("dns.anomaly-detector.llm-studio.timeout-seconds"));
        this.apiKey = getConfig().get("dns.anomaly-detector.llm-studio.api-key");

        String thresholdStr = getConfig().get("dns.anomaly-detector.trust-threshold");
        double threshold = 0.7;
        try {
            threshold = Double.parseDouble(thresholdStr);
        } catch (NumberFormatException e) {
            // оставить 0.7
        }
        this.trustThreshold = threshold;

        int ttlSeconds;
        try {
            ttlSeconds = getConfig().getInt("dns.anomaly-detector.processed-ttl-seconds");
        } catch (Exception e) {
            ttlSeconds = 3600; // дефолт 1 час
        }
        this.processedTtlMillis = ttlSeconds * 1000L;

        logger.info(LocaleUtil.getString("dns_anomaly_detector_initialized"),
                enabled, model, llmUrl, processedTtlMillis / 1000);
    }

    private boolean isProcessed(String domain, String clientIp) {
        return processedDomains.containsKey(domain) || processedClients.containsKey(clientIp);
    }

    private void markProcessed(String domain, String clientIp) {
        long now = System.currentTimeMillis();
        processedDomains.put(domain, now);
        processedClients.put(clientIp, now);
        logger.debug(LocaleUtil.getString("dns_anomaly_detector_domain_marked"),
                domain, clientIp, processedTtlMillis / 1000);
    }

    private void cleanupProcessed() {
        long now = System.currentTimeMillis();
        long expiryTime = now - processedTtlMillis;

        int removedDomains = 0;
        int removedClients = 0;

        // Очистка устаревших доменов
        for (Map.Entry<String, Long> entry : processedDomains.entrySet()) {
            if (entry.getValue() < expiryTime) {
                processedDomains.remove(entry.getKey());
                removedDomains++;
            }
        }

        // Очистка устаревших клиентов
        for (Map.Entry<String, Long> entry : processedClients.entrySet()) {
            if (entry.getValue() < expiryTime) {
                processedClients.remove(entry.getKey());
                removedClients++;
            }
        }

        if (removedDomains > 0 || removedClients > 0) {
            logger.info(LocaleUtil.getString("dns_anomaly_detector_cleanup"),
                    removedDomains, removedClients, processedTtlMillis / 1000);
        }
    }

    public void start() {
        if (!enabled) {
            logger.info(LocaleUtil.getString("dns_anomaly_detector_disabled"));
            return;
        }

        if (running) {
            logger.warn(LocaleUtil.getString("dns_anomaly_detector_already_running"));
            return;
        }

        running = true;
        executor.submit(this::processQueue);
        logger.info(LocaleUtil.getString("dns_anomaly_detector_started"), model);
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
        logger.info(LocaleUtil.getString("dns_anomaly_detector_stopped"));
    }

    public boolean isEnabled() {
        return enabled && running;
    }

    public void recordQuery(String clientIp, String domain, int queryType,
                            boolean isQuery, int opcode, boolean isTruncated,
                            boolean recursionDesired, int z, int rcode) {
        if (!enabled || !running) return;

        try {
            DnsQueryRecord record = new DnsQueryRecord(clientIp, domain, queryType,
                    System.currentTimeMillis(), isQuery, opcode, isTruncated,
                    recursionDesired, z, rcode);

            // Удалить только дубли по домену (не по clientIp!)
            queue.removeIf(r -> r.getDomain().equals(domain));

            queue.offer(record);
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_record_added"),
                    clientIp, domain, queryType);
        } catch (Exception e) {
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_queue_add_error"), e.getMessage());
        }
    }

    private void processQueue() {
        long lastCleanupTime = System.currentTimeMillis();
        long cleanupIntervalMillis = 10000; // Очистка раз в 10 секунд
        long lastLlmRequestTime = 0;
        long llmRequestIntervalMillis = 120000; // 120 секунд между запросами к LLM

        while (running) {
            try {
                long now = System.currentTimeMillis();

                // Ограничение частоты запросов к LLM
                if (now - lastLlmRequestTime < llmRequestIntervalMillis) {
                    Thread.sleep(100);
                    continue;
                }

                // Периодическая очистка устаревших записей
                if (now - lastCleanupTime > cleanupIntervalMillis) {
                    cleanupProcessed();
                    lastCleanupTime = now;
                    logger.info(LocaleUtil.getString("dns_anomaly_detector_cleanup_performed"),
                            processedTtlMillis / 1000);
                }

                DnsQueryRecord record = queue.poll(1, TimeUnit.SECONDS);

                if (record == null) {
                    continue;
                }

                String domain = record.getDomain();

                // Двойная проверка
                if (isProcessed(domain, record.getClientIp())) {
                    logger.debug(LocaleUtil.getString("dns_anomaly_detector_skip_processed"),
                            record.getClientIp(), domain);
                    continue;
                }

                // Сразу помечаем как обрабатываемый
                markProcessed(domain, record.getClientIp());

                logger.info(LocaleUtil.getString("dns_anomaly_detector_analyzing"),
                        record.getClientIp(), domain, record.getQueryType(), record.getEntropy());

                DnsAnalysisResult result = analyzeRecord(record);

                // Обновляем время последнего запроса к LLM
                lastLlmRequestTime = System.currentTimeMillis();

                if (result != null && result.isSuspicious() && result.getConfidence() >= trustThreshold) {
                    logger.info("{} {} {} {} {} {} {}",
                            LogFields.kv("event", "DNS_ANOMALY_DETECTED"),
                            LogFields.kv("client", record.getClientIp()),
                            LogFields.kv("domain", domain),
                            LogFields.kv("queryType", record.getQueryType()),
                            LogFields.kv("confidence", result.getConfidence()),
                            LogFields.kv("reason", result.getReason()),
                            LogFields.kv("timestamp", record.getTimestamp()));
                } else if (result != null) {
                    logger.info(LocaleUtil.getString("dns_anomaly_detector_not_suspicious"),
                            record.getClientIp(), domain, record.getQueryType(), result.getConfidence(), result.getReason());
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error(LocaleUtil.getString("dns_anomaly_detector_processing_error"), e.getMessage());
            }
        }

        logger.info(LocaleUtil.getString("dns_anomaly_detector_queue_completed"));
    }

    private DnsAnalysisResult analyzeRecord(DnsQueryRecord record) {
        if (llmUrl == null || llmUrl.isEmpty()) {
            logger.warn(LocaleUtil.getString("dns_anomaly_detector_llm_url_not_configured"));
            return null;
        }

        if (model == null || model.isEmpty()) {
            logger.warn(LocaleUtil.getString("dns_anomaly_detector_llm_model_not_configured"));
            return null;
        }

        try {
            String prompt = buildPrompt(record);

            logger.info(LocaleUtil.getString("dns_anomaly_detector_sending_request"), model, llmUrl);
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_prompt"), prompt);

            String response = sendToLlm(prompt);

            if (response == null || response.isEmpty()) {
                logger.warn(LocaleUtil.getString("dns_anomaly_detector_empty_response"));
                return null;
            }

            logger.debug(LocaleUtil.getString("dns_anomaly_detector_response"), response);

            return parseResponse(response);

        } catch (Exception e) {
            logger.error(LocaleUtil.getString("dns_anomaly_detector_analysis_error"), e.getMessage(), e);
            return null;
        }
    }

    private String buildPrompt(DnsQueryRecord record) {
        return loadPromptTemplate("prompts/dns_anomaly_prompt.txt")
                .replace("{clientIp}", record.getClientIp())
                .replace("{domain}", record.getDomain())
                .replace("{queryType}", String.valueOf(record.getQueryType()))
                .replace("{domainLength}", String.valueOf(record.getDomainLength()))
                .replace("{entropy}", String.format("%.2f", record.getEntropy()))
                .replace("{subdomainCount}", String.valueOf(record.getSubdomainCount()))
                .replace("{qr}", record.isQuery() ? "QUERY" : "RESPONSE")
                .replace("{opcode}", String.valueOf(record.getOpcode()))
                .replace("{tc}", record.isTruncated() ? "true" : "false")
                .replace("{rd}", record.isRecursionDesired() ? "true" : "false")
                .replace("{rcode}", String.valueOf(record.getRcode()));
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

        if (apiKey != null && !apiKey.isEmpty()) {
            builder.header("Authorization", "Bearer " + apiKey);
        }

        HttpRequest request = builder.build();

        logger.debug(LocaleUtil.getString("dns_anomaly_detector_http_request"), llmUrl);

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            logger.warn(LocaleUtil.getString("dns_anomaly_detector_llm_status"), response.statusCode());
            return null;
        }

        return response.body();
    }

    private DnsAnalysisResult parseResponse(String responseBody) {
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

            logger.debug(LocaleUtil.getString("dns_anomaly_detector_parsed_json"), content);

            boolean isSuspicious = content.contains("\"isSuspicious\":true");
            double confidence = extractConfidence(content);
            String reason = extractField(content, "reason");

            logger.info(LocaleUtil.getString("dns_anomaly_detector_analysis_result"),
                    isSuspicious, confidence, reason);

            return new DnsAnalysisResult(isSuspicious, confidence, reason, null);

        } catch (Exception e) {
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_parse_error"), e.getMessage());
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
            if (c == '"') {
                return i;
            }
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