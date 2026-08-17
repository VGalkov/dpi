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

        // TTL по умолчанию 1 час (3600 секунд)
        this.processedTtlMillis = getConfig().getInt("dns.anomaly-detector.processed-ttl-seconds") * 1000L;

        logger.info("DnsAnomalyDetector инициализирован: enabled={}, model={}, url={}, ttl={}s",
                enabled, model, llmUrl, processedTtlMillis / 1000);
    }

    private boolean isProcessed(String domain, String clientIp) {
        return processedDomains.containsKey(domain) || processedClients.containsKey(clientIp);
    }

    private void markProcessed(String domain, String clientIp) {
        long now = System.currentTimeMillis();
        processedDomains.put(domain, now);
        processedClients.put(clientIp, now);
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
            logger.info("DnsAnomalyDetector: очистка устаревших записей: domains={}, clients={}",
                    removedDomains, removedClients);
        }
    }

    public void start() {
        if (!enabled) {
            logger.info("DnsAnomalyDetector отключён в конфиге");
            return;
        }

        if (running) {
            logger.warn("DnsAnomalyDetector уже запущен");
            return;
        }

        running = true;
        executor.submit(this::processQueue);
        logger.info("DnsAnomalyDetector запущен, модель={}", model);
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
        logger.info("DnsAnomalyDetector остановлен");
    }

    public boolean isEnabled() {
        return enabled && running;
    }

    public void recordQuery(String clientIp, String domain, int queryType) {
        if (!enabled || !running) return;

        // Проверка до добавления в очередь
        if (isProcessed(domain, clientIp)) {
            return;
        }

        try {
            DnsQueryRecord record = new DnsQueryRecord(clientIp, domain, queryType, System.currentTimeMillis());

            // Удалить все существующие записи с таким же доменом из очереди
            queue.removeIf(r -> r.getDomain().equals(domain) || r.getClientIp().equals(clientIp));

            queue.offer(record);
            logger.debug("DnsAnomalyDetector: запись добавлена в очередь: client={}, domain={}, queryType={}",
                    clientIp, domain, queryType);
        } catch (Exception e) {
            logger.debug("Ошибка добавления записи в очередь: {}", e.getMessage());
        }
    }

    private void processQueue() {
        long lastCleanupTime = System.currentTimeMillis();
        long cleanupIntervalMillis = 60000; // Очистка раз в минуту

        while (running) {
            try {
                // Периодическая очистка устаревших записей
                long now = System.currentTimeMillis();
                if (now - lastCleanupTime > cleanupIntervalMillis) {
                    cleanupProcessed();
                    lastCleanupTime = now;
                    logger.debug("DnsAnomalyDetector: очистка processedDomains/processedClients выполнена");
                }

                DnsQueryRecord record = queue.poll(1, TimeUnit.SECONDS);

                if (record == null) {
                    continue;
                }

                String domain = record.getDomain();

                // Двойная проверка
                if (isProcessed(domain, record.getClientIp())) {
                    logger.debug("DnsAnomalyDetector: пропуск записи (уже обработано): client={}, domain={}",
                            record.getClientIp(), domain);
                    continue;
                }

                // Сразу помечаем как обрабатываемый
                markProcessed(domain, record.getClientIp());

                logger.info("DnsAnomalyDetector: анализ записи: client={}, domain={}, queryType={}, entropy={}",
                        record.getClientIp(), domain, record.getQueryType(), record.getEntropy());

                DnsAnalysisResult result = analyzeRecord(record);

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
                    logger.info("DnsAnomalyDetector: запрос не подозрителен: client={}, domain={}, confidence={}, reason={}",
                            record.getClientIp(), domain, result.getConfidence(), result.getReason());
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Ошибка обработки записи: {}", e.getMessage());
            }
        }

        logger.info("DnsAnomalyDetector завершил обработку очереди");
    }

    private DnsAnalysisResult analyzeRecord(DnsQueryRecord record) {
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

            logger.info("DnsAnomalyDetector: отправка запроса в LLM Studio: model={}, url={}", model, llmUrl);
            logger.debug("DnsAnomalyDetector: промпт: {}", prompt);

            String response = sendToLlm(prompt);

            if (response == null || response.isEmpty()) {
                logger.warn("DnsAnomalyDetector: пустой ответ от LLM Studio");
                return null;
            }

            logger.debug("DnsAnomalyDetector: ответ LLM Studio: {}", response);

            return parseResponse(response);

        } catch (Exception e) {
            logger.error("Ошибка анализа записи: {}", e.getMessage(), e);
            return null;
        }
    }

    private String buildPrompt(DnsQueryRecord record) {
        return String.format(
                "Ты — система безопасности, анализирующая DNS-трафик на аномалии.\n\n" +
                        "Проанализируй DNS-запрос:\n" +
                        "- Client IP: %s\n" +
                        "- Domain: %s\n" +
                        "- Query Type: %d\n" +
                        "- Domain Length: %d\n" +
                        "- Entropy: %.2f\n" +
                        "- Subdomain Count: %d\n\n" +
                        "Критерии подозрительности:\n" +
                        "1. DNS tunneling — очень длинные домены (>50 символов), высокая энтропия (>3.5), много поддоменов (>5).\n" +
                        "2. DGA-домены — случайные наборы символов, отсутствие осмысленных слов.\n" +
                        "3. TXT-запросы к подозрительным доменам — возможный C2-канал.\n" +
                        "4. Частые запросы к одному домену с одного IP (>10 запросов в минуту) — возможный бот или сканер.\n" +
                        "5. Запросы к доменам с цифрами и дефисами в случайном порядке (например, a1b2-c3d4.xyz) — возможный DGA.\n" +
                        "6. Запросы к доменам с необычными TLD (.xyz, .top, .club, .work) — часто используются для спама.\n" +
                        "7. Запросы к доменам, которые были зарегистрированы недавно (<30 дней) — возможный фишинг.\n" +
                        "8. Запросы с нестандартными типами записей (NULL, CNAME на внешние домены, множественные TXT) — возможный C2.\n" +
                        "9. Запросы к доменам с IP-адресами в имени (например, 192-168-1-1.example.com) — возможный обход blacklist.\n" +
                        "10. Запросы к доменам, которые содержат ключевые слова (malware, phishing, hack, exploit) — явная угроза.\n\n" +
                        "Ответь ТОЛЬКО в формате JSON:\n" +
                        "{\n" +
                        "  \"isSuspicious\": true/false,\n" +
                        "  \"confidence\": 0.0-1.0,\n" +
                        "  \"reason\": \"краткое объяснение\",\n" +
                        "  \"recommendedActions\": [\"BLOCK_DOMAIN\", \"LOG_ONLY\", \"NONE\"]\n" +
                        "}",
                record.getClientIp(),
                record.getDomain(),
                record.getQueryType(),
                record.getDomainLength(),
                record.getEntropy(),
                record.getSubdomainCount()
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

        if (apiKey != null && !apiKey.isEmpty()) {
            builder.header("Authorization", "Bearer " + apiKey);
        }

        HttpRequest request = builder.build();

        logger.debug("DnsAnomalyDetector: HTTP-запрос к LLM Studio: {}", llmUrl);

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            logger.warn("LLM Studio вернул статус: {}", response.statusCode());
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

            logger.debug("DnsAnomalyDetector: распарсенный JSON от LLM: {}", content);

            boolean isSuspicious = content.contains("\"isSuspicious\":true");
            double confidence = extractConfidence(content);
            String reason = extractField(content, "reason");

            logger.info("DnsAnomalyDetector: результат анализа: isSuspicious={}, confidence={}, reason={}",
                    isSuspicious, confidence, reason);

            return new DnsAnalysisResult(isSuspicious, confidence, reason, null);

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
