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

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
/**
 * ✅ Оптимизация п.15: общий клиент для LLM Studio
 */
public final class LlmClient {
    private static final Logger logger = LoggerFactory.getLogger(LlmClient.class);

    private final String llmUrl;
    private final String model;
    private final Duration timeout;
    private final String apiKey;
    private final HttpClient httpClient;

    public LlmClient(String llmUrl, String model, int timeoutSeconds, String apiKey) {
        this.llmUrl = llmUrl;
        this.model = model;
        this.timeout = Duration.ofSeconds(timeoutSeconds);
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /**
     * ✅ Общий метод для отправки запроса в LLM
     */
    public String sendRequest(String prompt) {
        if (llmUrl == null || llmUrl.isEmpty() || model == null || model.isEmpty()) {
            logger.warn(LocaleUtil.getString("dns_anomaly_detector_llm_url_not_configured"));
            return null;
        }

        try {
            String escapedPrompt = escapeJson(prompt);
            String jsonBody = buildJsonBody(escapedPrompt);

            logger.info(LocaleUtil.getString("llm_client_sending_request"), model, llmUrl);

            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(llmUrl))
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody));

            if (apiKey != null && !apiKey.isEmpty()) {
                builder.header("Authorization", "Bearer " + apiKey);
            }

            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                logger.warn(LocaleUtil.getString("llm_client_response_received"), response.statusCode());
                return null;
            }

            logger.debug(LocaleUtil.getString("llm_client_response_received"), response.statusCode());
            return response.body();

        } catch (IOException e) {
            logger.error(LocaleUtil.getString("llm_client_error"), e.getMessage(), e);
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.error(LocaleUtil.getString("llm_client_error"), e.getMessage(), e);
            return null;
        }
    }

    /**
     * ✅ П.3: Оптимизированный метод для парсинга ответа LLM
     */
    public AnalysisResult parseResponse(String responseBody) {
        try {
            // ✅ П.3: Упрощённый парсинг через indexOf
            String content = extractContent(responseBody);
            if (content == null) return null;

            boolean isSuspicious = content.contains("\"isSuspicious\":true") ||
                    content.contains("\"isSuspicious\": true");
            double confidence = extractConfidence(content);
            String reason = extractField(content, "reason");

            logger.debug(LocaleUtil.getString("dns_anomaly_detector_parsed_json"), content);
            logger.info(LocaleUtil.getString("dns_anomaly_detector_analysis_result"),
                    isSuspicious, confidence, reason);

            return new AnalysisResult(isSuspicious, confidence, reason, null);

        } catch (Exception e) {
            logger.debug(LocaleUtil.getString("llm_client_parse_error"), e.getMessage());
            return null;
        }
    }

    /**
     * ✅ П.3: Выделение content из JSON ответа
     */
    private String extractContent(String responseBody) {
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

        return responseBody.substring(quoteStart + 1, quoteEnd)
                .replace("\\\"", "\"")
                .replace("\\n", "\n");
    }

    /**
     * ✅ Общий метод для загрузки шаблона промпта
     */
    public String loadPromptTemplate(String resourceName) {
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

    /**
     * ✅ Экранирование JSON
     */
    private String escapeJson(String prompt) {
        return prompt.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * ✅ Построение JSON тела запроса
     */
    private String buildJsonBody(String escapedPrompt) {
        return String.format(
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
    }

    /**
     * ✅ Поиск закрывающей кавычки
     */
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

    /**
     * ✅ Извлечение confidence
     */
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

    /**
     * ✅ Извлечение поля из JSON
     */
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