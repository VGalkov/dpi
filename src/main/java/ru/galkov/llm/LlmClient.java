package ru.galkov.llm;

import com.fasterxml.jackson.databind.JsonNode;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 *
 * ✅ П.19: Jackson ObjectMapper для надёжного парсинга JSON
 */
public final class LlmClient {
    private static final Logger logger = LoggerFactory.getLogger(LlmClient.class);

    private final String llmUrl;
    private final String model;
    private final Duration timeout;
    private final String apiKey;
    private final HttpClient httpClient;

    // ✅ П.19: Jackson ObjectMapper для парсинга
    private static final com.fasterxml.jackson.databind.ObjectMapper objectMapper =
            new com.fasterxml.jackson.databind.ObjectMapper();

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
     * ✅ П.19: Jackson ObjectMapper для надёжного парсинга JSON
     */
    public AnalysisResult parseResponse(String responseBody) {
        try {
            // ✅ П.19: Парсинг через Jackson
            JsonNode rootNode = objectMapper.readTree(responseBody);

            // Извлечение content из choices[0].message.content
            String content = extractContentFromJson(rootNode);
            if (content == null || content.isEmpty()) {
                logger.warn(LocaleUtil.getString("llm_client_invalid_response_structure"), "choices[0].message.content");
                return null;
            }

            // Парсинг JSON из content
            JsonNode resultNode = objectMapper.readTree(content);

            // Валидация полей
            if (!resultNode.has("isSuspicious")) {
                logger.warn(LocaleUtil.getString("llm_client_invalid_response_structure"), "isSuspicious");
                return null;
            }
            if (!resultNode.has("confidence")) {
                logger.warn(LocaleUtil.getString("llm_client_invalid_response_structure"), "confidence");
                return null;
            }
            if (!resultNode.has("reason")) {
                logger.warn(LocaleUtil.getString("llm_client_invalid_response_structure"), "reason");
                return null;
            }

            // Извлечение и валидация isSuspicious
            JsonNode suspiciousNode = resultNode.get("isSuspicious");
            if (!suspiciousNode.isBoolean()) {
                logger.warn(LocaleUtil.getString("llm_client_invalid_suspicious_value"), suspiciousNode.asText());
                return null;
            }
            boolean isSuspicious = suspiciousNode.asBoolean();

            // Извлечение и валидация confidence
            JsonNode confidenceNode = resultNode.get("confidence");
            if (!confidenceNode.isNumber()) {
                logger.warn(LocaleUtil.getString("llm_client_invalid_confidence_value"), confidenceNode.asText());
                return null;
            }
            double confidence = confidenceNode.asDouble();
            if (confidence < 0.0 || confidence > 1.0) {
                logger.warn(LocaleUtil.getString("llm_client_invalid_confidence_value"), confidence);
                confidence = Math.max(0.0, Math.min(1.0, confidence));
            }

            // Извлечение reason
            String reason = resultNode.has("reason") ? resultNode.get("reason").asText("") : "";

            // Извлечение recommendedActions
            List<String> recommendedActions = new ArrayList<>();
            if (resultNode.has("recommendedActions") && resultNode.get("recommendedActions").isArray()) {
                JsonNode actionsNode = resultNode.get("recommendedActions");
                for (JsonNode actionNode : actionsNode) {
                    if (actionNode.isTextual()) {
                        recommendedActions.add(actionNode.asText());
                    }
                }
            }

            logger.debug(LocaleUtil.getString("dns_anomaly_detector_parsed_json"), content);
            logger.info(LocaleUtil.getString("dns_anomaly_detector_analysis_result"),
                    isSuspicious, confidence, reason);

            return new AnalysisResult(isSuspicious, confidence, reason,
                    recommendedActions.isEmpty() ? Collections.emptyList() : Collections.unmodifiableList(recommendedActions));

        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            logger.error(LocaleUtil.getString("llm_client_json_parse_error"), e.getMessage());
            return null;
        } catch (Exception e) {
            logger.debug(LocaleUtil.getString("llm_client_parse_error"), e.getMessage());
            return null;
        }
    }

    /**
     * ✅ П.19: Извлечение content из JSON ответа через Jackson
     */
    private String extractContentFromJson(JsonNode rootNode) {
        try {
            JsonNode choicesNode = rootNode.get("choices");
            if (choicesNode == null || !choicesNode.isArray() || choicesNode.size() == 0) {
                return null;
            }

            JsonNode firstChoice = choicesNode.get(0);
            if (firstChoice == null) {
                return null;
            }

            JsonNode messageNode = firstChoice.get("message");
            if (messageNode == null) {
                return null;
            }

            JsonNode contentNode = messageNode.get("content");
            if (contentNode == null || !contentNode.isTextual()) {
                return null;
            }

            return contentNode.asText();

        } catch (Exception e) {
            logger.debug("Error extracting content from JSON: {}", e.getMessage());
            return null;
        }
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
}