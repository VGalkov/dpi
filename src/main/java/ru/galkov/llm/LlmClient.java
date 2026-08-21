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
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public final class LlmClient {
    private static final Logger logger = LoggerFactory.getLogger(LlmClient.class);

    private static final int MAX_OUTPUT_TOKENS = 2048;
    private static final int MAX_RESPONSE_BYTES = 1_048_576;
    private static final int MAX_REASON_LENGTH = 500;
    private static final double TOP_P = 0.9;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final String llmUrl;
    private final String model;
    private final Duration timeout;
    private final String apiKey;
    private final HttpClient httpClient;

    public LlmClient(String llmUrl, String model, int timeoutSeconds, String apiKey) {
        if (llmUrl == null || llmUrl.isBlank()) throw new IllegalArgumentException("LLM URL cannot be null or blank");
        if (model == null || model.isBlank()) throw new IllegalArgumentException("LLM model cannot be null or blank");
        if (timeoutSeconds <= 0) throw new IllegalArgumentException("LLM timeout must be positive");


        this.llmUrl = llmUrl;
        this.model = model;
        this.timeout = Duration.ofSeconds(timeoutSeconds);
        this.apiKey = apiKey == null ? "" : apiKey;

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .proxy(ProxySelector.of(null))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public String sendRequest(String prompt) {
        if (prompt == null || prompt.isBlank()) {
            logger.warn("Cannot send empty LLM prompt");
            return null;
        }

        try {
            ObjectNode root = objectMapper.createObjectNode();
            root.put("model", model);
            root.put("temperature", 0.0);
            root.put("max_tokens", MAX_OUTPUT_TOKENS);
            root.put("stream", false);
            root.put("reasoning", false);
            root.put("top_p", TOP_P);

            ObjectNode systemMessage = objectMapper.createObjectNode();
            systemMessage.put("role", "system");
            systemMessage.put("content",
                    "Return only one valid compact JSON object. "
                            + "Do not reason aloud. "
                            + "Do not use Markdown. "
                            + "Do not add any text before or after JSON.");

            ObjectNode userMessage = objectMapper.createObjectNode();
            userMessage.put("role", "user");
            userMessage.put("content", prompt);

            ArrayNode messages = objectMapper.createArrayNode();
            messages.add(systemMessage);
            messages.add(userMessage);

            root.set("messages", messages);

            String jsonBody = objectMapper.writeValueAsString(root);
            logger.info(LocaleUtil.getString("llm_client_sending_request"), model, llmUrl);

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(llmUrl))
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));

            if (!apiKey.isBlank()) {
                requestBuilder.header("Authorization", "Bearer " + apiKey);
            }

            HttpResponse<String> response = httpClient.send(
                    requestBuilder.build(),
                    responseInfo -> HttpResponse.BodySubscribers.limiting(
                            HttpResponse.BodySubscribers.ofString(StandardCharsets.UTF_8),
                            MAX_RESPONSE_BYTES
                    )
            );

            String responseBody = response.body();

            if (response.statusCode() != 200) {
                logger.warn("LLM API returned error status={}: {}", response.statusCode(), llmUrl);
                logger.warn("LM Studio error body: {}", truncate(responseBody, 4000));
                return null;
            }

            if (responseBody == null || responseBody.isBlank()) {
                logger.warn("LM Studio returned an empty response");
                return null;
            }

            logger.debug("LLM response received: status={}", response.statusCode());
            return responseBody;

        } catch (IOException | RuntimeException e) {
            logger.error(LocaleUtil.getString("llm_client_error"), e.getMessage(), e);
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.error(LocaleUtil.getString("llm_client_error"), e.getMessage(), e);
            return null;
        }
    }

    public AnalysisResult parseResponse(String responseBody, String domain) {
        if (responseBody == null || responseBody.isBlank()) {
            logger.warn("Empty LLM response body for domain={}", domain);
            return new AnalysisResult(false, 0.0, "Empty response from LLM", List.of("NONE"));
        }

        try {
            JsonNode rootNode = objectMapper.readTree(responseBody);

            JsonNode choicesNode = rootNode.get("choices");
            if (choicesNode == null || !choicesNode.isArray() || choicesNode.isEmpty()) {
                logger.warn("No choices in LLM response for domain={}", domain);
                return new AnalysisResult(false, 0.0, "Invalid LLM response structure (no choices)", List.of("NONE"));
            }

            JsonNode messageNode = choicesNode.get(0).get("message");
            if (messageNode == null) {
                logger.warn("Message missing in LLM response for domain={}", domain);
                return new AnalysisResult(false, 0.0, "Invalid LLM response (no message)", List.of("NONE"));
            }

            String rawContent = messageNode.get("content").asText();

            logger.trace("Raw LLM content (before cleaning) for domain={}: {}", domain, truncate(rawContent, 500));

            if (rawContent.isBlank()) {
                logger.warn("Content is empty for domain={}", domain);
                return new AnalysisResult(false, 0.0, "LLM returned empty content", List.of("NONE"));
            }

            String cleanJson = extractPureJson(rawContent);

            if (cleanJson != null) {
                logger.trace("Cleaned JSON extracted for domain={}: {}", domain, truncate(cleanJson, 500));
            } else {
                logger.error("Failed to extract valid JSON from raw content for domain={}. Raw: {}", domain, truncate(rawContent, 200));
                return new AnalysisResult(false, 0.0, "Failed to extract JSON from response", List.of("NONE"));
            }

            JsonNode resultNode = objectMapper.readTree(cleanJson);
            if (!resultNode.isObject()) {
                logger.error("Extracted content is not a JSON object for domain={}", domain);
                return new AnalysisResult(false, 0.0, "Extracted content is not JSON object", List.of("NONE"));
            }

            JsonNode suspiciousNode = resultNode.get("isSuspicious");
            JsonNode confidenceNode = resultNode.get("confidence");
            JsonNode reasonNode = resultNode.get("reason");
            JsonNode actionsNode = resultNode.get("recommendedActions");

            if (suspiciousNode == null && resultNode.has("__isSuspicious__")) suspiciousNode = resultNode.get("__isSuspicious__");
            if (suspiciousNode == null && resultNode.has("is_suspicious")) suspiciousNode = resultNode.get("is_suspicious");

            if (confidenceNode == null && resultNode.has("_confidence_")) confidenceNode = resultNode.get("_confidence_");
            if (confidenceNode == null && resultNode.has("conf")) confidenceNode = resultNode.get("conf");

            if (reasonNode == null && resultNode.has("_reason_")) reasonNode = resultNode.get("_reason_");

            if (actionsNode == null && resultNode.has("_recommendedActions_")) actionsNode = resultNode.get("_recommendedActions_");
            if (actionsNode == null && resultNode.has("action")) actionsNode = resultNode.get("action");

            if (suspiciousNode == null || confidenceNode == null) {
                logger.warn("Missing mandatory fields in JSON for domain={}. Required: isSuspicious, confidence.", domain);

                List<String> availableKeys = new ArrayList<>();
                for (Iterator<String> it = resultNode.fieldNames(); it.hasNext(); ) {
                    String key = it.next();
                    availableKeys.add(key);
                }
                logger.warn("Available keys in response for domain={}: {}", domain, availableKeys);

                return new AnalysisResult(false, 0.0, "Missing critical fields in LLM output", List.of("NONE"));
            }

            boolean isSuspicious = suspiciousNode.asBoolean();
            double confidence = confidenceNode.asDouble();

            if (!Double.isFinite(confidence)) {
                confidence = 0.0;
            } else if (confidence < 0.0) confidence = 0.0;
            else if (confidence > 1.0) confidence = 1.0;

            String reason = "";
            if (reasonNode != null && reasonNode.isTextual()) {
                reason = reasonNode.asText().trim();
            }
            if (reason.length() > MAX_REASON_LENGTH) {
                reason = reason.substring(0, MAX_REASON_LENGTH);
            }

            List<String> actions = new ArrayList<>();
            if (actionsNode != null) {
                if (actionsNode.isArray()) {
                    for (JsonNode item : actionsNode) {
                        if (item.isTextual()) actions.add(item.asText());
                    }
                } else if (actionsNode.isTextual()) {
                    String singleAction = actionsNode.asText();
                    logger.info("Model returned string in 'recommendedActions' instead of array for domain={}. Value: '{}'. Converting to list.", domain, singleAction);
                    actions.add(singleAction);
                }
            }

            if (actions.isEmpty()) {
                JsonNode singleActionNode = resultNode.get("action");
                if (singleActionNode != null && singleActionNode.isTextual()) {
                    actions.add(singleActionNode.asText());
                }
            }

            if (actions.isEmpty()) {
                actions.add("NONE");
                logger.debug("No action field found in LLM response for domain={}, defaulting to NONE", domain);
            }

            logger.info("Successfully parsed LLM result: domain={}, suspicious={}, confidence={}, actions={}",
                    domain, isSuspicious, String.format(Locale.ROOT, "%.2f", confidence), actions);

            return new AnalysisResult(isSuspicious, confidence, reason, actions);

        } catch (IOException e) {
            logger.error("Critical JSON parsing error for domain={}: {}", domain, e.getMessage(), e);
            return new AnalysisResult(false, 0.0, "Parsing failed: " + e.getMessage(), List.of("NONE"));
        } catch (Exception e) {
            logger.error("Unexpected error during LLM parsing for domain={}: {}", domain, e.getMessage(), e);
            return new AnalysisResult(false, 0.0, "Unexpected error", List.of("NONE"));
        }
    }

    private String extractPureJson(String input) {
        if (input == null) return null;
        String trimmed = input.trim();

        int start = trimmed.indexOf('{');
        int end = trimmed.lastIndexOf('}');

        if (start != -1 && end != -1 && end > start) {
            String candidate = trimmed.substring(start, end + 1);
            try {
                objectMapper.readTree(candidate);
                return candidate;
            } catch (IOException ignored) {
                return findValidJsonBlock(trimmed);
            }
        }
        return null;
    }

    private String findValidJsonBlock(String str) {
        int len = str.length();
        for (int i = 0; i < len; i++) {
            if (str.charAt(i) == '{') {
                for (int j = len - 1; j > i; j--) {
                    if (str.charAt(j) == '}') {
                        String candidate = str.substring(i, j + 1);
                        try {
                            objectMapper.readTree(candidate);
                            return candidate;
                        } catch (IOException ignore) {}
                    }
                }
            }
        }
        return null;
    }

    public String loadPromptTemplate(String resourceName) {
        if (resourceName == null || resourceName.isBlank()) {
            return "";
        }

        try (InputStream input = getClass().getClassLoader().getResourceAsStream(resourceName)) {
            if (input == null) {
                logger.warn("Prompt template not found: {}", resourceName);
                return "";
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.error("Prompt template loading failed: {}", resourceName, e);
            return "";
        }
    }

    private static String truncate(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength) + "...";
    }
}