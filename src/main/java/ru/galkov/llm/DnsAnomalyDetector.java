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

        int ttlSeconds;
        try {
            ttlSeconds = getConfig().getInt("dns.anomaly-detector.processed-ttl-seconds");
        } catch (Exception e) {
            ttlSeconds = 3600; // дефолт 1 час
        }
        this.processedTtlMillis = ttlSeconds * 1000L;

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
        logger.debug("DnsAnomalyDetector: домен помечен как обработанный: domain={}, clientIp={}, ttl={}s",
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
            logger.info("DnsAnomalyDetector: очистка устаревших записей: domains={}, clients={}, ttl={}s",
                    removedDomains, removedClients, processedTtlMillis / 1000);
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
            logger.debug("DnsAnomalyDetector: запись добавлена в очередь: client={}, domain={}, queryType={}",
                    clientIp, domain, queryType);
        } catch (Exception e) {
            logger.debug("Ошибка добавления записи в очередь: {}", e.getMessage());
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
                    logger.info("DnsAnomalyDetector: очистка processedDomains/processedClients выполнена, ttl={}s",
                            processedTtlMillis / 1000);
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
                    logger.info("DnsAnomalyDetector: запрос не подозрителен: client={}, domain={}, queryType={}, confidence={}, reason={}",
                            record.getClientIp(), domain, record.getQueryType(), result.getConfidence(), result.getReason());
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
                        "- Query Type: %d (1=A, 28=AAAA, 16=TXT, 12=PTR, 5=CNAME, 15=MX)\n" +
                        "- Domain Length: %d символов\n" +
                        "- Entropy: %.2f (норма: 2.5-3.5, подозрительно: >4.0)\n" +
                        "- Subdomain Count: %d (норма: 1-3, подозрительно: >5)\n" +
                        "- DNS Header:\n" +
                        "  * QR: %s (QUERY=норма, RESPONSE=аномалия для запроса)\n" +
                        "  * Opcode: %d (0=standard query, 1=inverse, 2=status, 4=notify)\n" +
                        "  * TC: %s (false=норма, true=возможна атака на переполнение)\n" +
                        "  * RD: %s (true=норма, false=аномалия для клиента)\n" +
                        "  * RCODE: %d (0=no error, 3=NXDOMAIN, 5=refused)\n\n" +
                        "Критерии подозрительности (оцени по шкале 0-1):\n" +
                        "1. DNS tunneling: domainLength>50 И entropy>3.5 И subdomainCount>5 → confidence=0.9\n" +
                        "2. DGA-домен: entropy>4.0 И домен содержит случайные цифры/буквы (a1b2c3.xyz) → confidence=0.8\n" +
                        "3. C2-канал: queryType=16 (TXT) И entropy>3.5 → confidence=0.7\n" +
                        "4. Атака на переполнение: TC=true → confidence=0.6\n" +
                        "5. Сканер/разведка: Opcode!=0 ИЛИ QR=RESPONSE в запросе → confidence=0.8\n" +
                        "6. DGA-сканер: queryType=1 (A) И RCODE=3 (NXDOMAIN) И entropy>3.5 → confidence=0.7\n" +
                        "7. Подозрительный TLD: домен заканчивается на .xyz/.top/.club/.work/.tk → confidence=0.5\n" +
                        "8. IP в домене: домен содержит цифры и дефисы (192-168-1-1.example.com) → confidence=0.6\n\n" +
                        "9. Частые запросы: один IP делает >10 запросов к разным доменам за 1 минуту → confidence=0.6\n" +
                        "10. Запрос к известному malicious-домену (если есть в списке) → confidence=0.95\n" +
                        "11. Запрос к домену с keywords (malware, phishing, hack, exploit) → confidence=0.8\n" +
                        "Правила принятия решения:\n" +
                        "- isSuspicious=true, если confidence>=0.7\n" +
                        "- isSuspicious=false, если confidence<0.7\n" +
                        "- recommendedActions=[\"BLOCK_DOMAIN\"], если confidence>=0.8\n" +
                        "- recommendedActions=[\"LOG_ONLY\"], если 0.7<=confidence<0.8\n" +
                        "- recommendedActions=[\"NONE\"], если confidence<0.7\n\n" +
                        "Ответь ТОЛЬКО в формате JSON:\n" +
                        "{\n" +
                        "  \"isSuspicious\": true/false,\n" +
                        "  \"confidence\": 0.0-1.0,\n" +
                        "  \"reason\": \"краткое объяснение (1-2 предложения)\",\n" +
                        "  \"recommendedActions\": [\"BLOCK_DOMAIN\"/\"LOG_ONLY\"/\"NONE\"]\n" +
                        "}",
                record.getClientIp(),
                record.getDomain(),
                record.getQueryType(),
                record.getDomainLength(),
                record.getEntropy(),
                record.getSubdomainCount(),
                record.isQuery() ? "QUERY" : "RESPONSE",
                record.getOpcode(),
                record.isTruncated() ? "true" : "false",
                record.isRecursionDesired() ? "true" : "false",
                record.getRcode()
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