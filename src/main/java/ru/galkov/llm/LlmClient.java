package ru.galkov.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
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

public final class LlmClient {
    private static final Logger logger = LoggerFactory.getLogger(LlmClient.class);

    private final String llmUrl;
    private final String model;
    private final Duration timeout;
    private final String apiKey;
    private final HttpClient httpClient;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public LlmClient(String llmUrl, String model, int timeoutSeconds, String apiKey) {
        this.llmUrl = llmUrl;
        this.model = model;
        this.timeout = Duration.ofSeconds(timeoutSeconds);
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public String sendRequest(String prompt) {
        if (llmUrl == null || llmUrl.isEmpty() || model == null || model.isEmpty()) {
            logger.warn(LocaleUtil.getString("dns_anomaly_detector_llm_url_not_configured"));
            return null;
        }

        try {
            ObjectNode root = objectMapper.createObjectNode();
            root.put("model", model);

            ObjectNode message = objectMapper.createObjectNode();
            message.put("role", "user");
            message.put("content", prompt);

            ArrayNode messages = objectMapper.createArrayNode();
            messages.add(message);
            root.set("messages", messages);

            root.put("temperature", 0.1);
            root.put("max_tokens", 500);

            String jsonBody = objectMapper.writeValueAsString(root);

            logger.info(LocaleUtil.getString("llm_client_sending_request"), model, llmUrl);

            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(llmUrl))
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody));

            if (apiKey != null && !apiKey.isEmpty()) {
                builder.header("Authorization", "Bearer " + apiKey);
            }

            HttpResponse<String> response = httpClient.send(
                    builder.build(),
                    HttpResponse.BodyHandlers.ofString()
            );

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

    public AnalysisResult parseResponse(String responseBody) {
        if (responseBody == null || responseBody.trim().isEmpty()) {
            logger.warn("Empty response body");
            return null;
        }

        try {
            JsonNode rootNode = objectMapper.readTree(responseBody);

            String content = extractContentFromJson(rootNode);
            if (content == null || content.isEmpty()) {
                logger.warn(LocaleUtil.getString("llm_client_invalid_response_structure"), "choices[0].message.content");
                return null;
            }

            JsonNode resultNode = objectMapper.readTree(content);

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

            JsonNode suspiciousNode = resultNode.get("isSuspicious");
            if (!suspiciousNode.isBoolean()) {
                logger.warn(LocaleUtil.getString("llm_client_invalid_suspicious_value"), suspiciousNode.asText());
                return null;
            }
            boolean isSuspicious = suspiciousNode.asBoolean();

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

            String reason = resultNode.has("reason") ? resultNode.get("reason").asText("") : "";

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

            return new AnalysisResult(
                    isSuspicious,
                    confidence,
                    reason,
                    recommendedActions.isEmpty()
                            ? Collections.emptyList()
                            : Collections.unmodifiableList(recommendedActions)
            );

        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            logger.error(LocaleUtil.getString("llm_client_json_parse_error"), e.getMessage());
            return null;
        } catch (Exception e) {
            logger.debug(LocaleUtil.getString("llm_client_parse_error"), e.getMessage());
            return null;
        }
    }

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
}