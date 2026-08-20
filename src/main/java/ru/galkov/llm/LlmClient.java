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
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Искусственный интеллект.
 */
public final class LlmClient {
    private static final Logger logger = LoggerFactory.getLogger(LlmClient.class);

    private static final int MAX_RESPONSE_BYTES = 1_048_576;
    private static final int MAX_REASON_LENGTH = 500;
    private static final int MAX_OUTPUT_TOKENS = 1000;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static final Pattern JSON_PATTERN = Pattern.compile(
            "```(?:json)?\\s*(\\{.*?})\\s*```",
            Pattern.DOTALL
    );

    private final String llmUrl;
    private final String model;
    private final Duration timeout;
    private final String apiKey;
    private final HttpClient httpClient;

    public LlmClient(String llmUrl, String model, int timeoutSeconds, String apiKey) {
        if (llmUrl == null || llmUrl.isBlank()) {
            throw new IllegalArgumentException("LLM URL cannot be null or blank");
        }
        if (model == null || model.isBlank()) {
            throw new IllegalArgumentException("LLM model cannot be null or blank");
        }
        if (timeoutSeconds <= 0) {
            throw new IllegalArgumentException("LLM timeout must be positive");
        }

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

            // ✅ П.54: лимит применяется ВО ВРЕМЯ чтения, а не после.
            //        Ответ больше MAX_RESPONSE_BYTES не аллоцируется целиком
            //        (работает на Java 11+ через BodySubscribers.limiting).
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

    public AnalysisResult parseResponse(String responseBody) {
        if (responseBody == null || responseBody.isBlank()) {
            logger.warn("Empty LLM response body");
            return null;
        }

        try {
            String cleanedJson = extractJsonFromMarkdown(responseBody);
            JsonNode rootNode = objectMapper.readTree(cleanedJson);

            JsonNode choicesNode = rootNode.get("choices");
            if (choicesNode == null || !choicesNode.isArray() || choicesNode.isEmpty()) {
                logger.warn("LLM response does not contain choices");
                return null;
            }

            JsonNode firstChoice = choicesNode.get(0);
            JsonNode messageNode = firstChoice.get("message");
            if (messageNode == null || !messageNode.isObject()) {
                logger.warn("LLM response does not contain message");
                return null;
            }

            JsonNode finishReason = firstChoice.get("finish_reason");
            if (finishReason != null && "length".equals(finishReason.asText())) {
                logger.warn("LLM output was truncated by max_tokens");
                return null;
            }

            JsonNode contentNode = messageNode.get("content");
            if (contentNode == null || !contentNode.isTextual() || contentNode.asText().isBlank()) {
                JsonNode reasoningNode = messageNode.get("reasoning_content");
                logger.warn("LLM message.content is empty; reasoningContent={}",
                        reasoningNode == null ? "none" : truncate(reasoningNode.asText(), 500));
                return null;
            }

            String content = contentNode.asText().trim();
            String cleanedContent = extractJsonFromMarkdown(content);
            JsonNode resultNode = objectMapper.readTree(cleanedContent);

            if (!resultNode.isObject()) {
                logger.warn("LLM content is not a JSON object");
                return null;
            }

            JsonNode suspiciousNode = resultNode.get("isSuspicious");
            JsonNode confidenceNode = resultNode.get("confidence");
            JsonNode reasonNode = resultNode.get("reason");
            JsonNode actionsNode = resultNode.get("recommendedActions");

            if (suspiciousNode == null || confidenceNode == null || reasonNode == null || actionsNode == null) {
                logger.warn("LLM JSON misses required fields");
                return null;
            }
            if (!suspiciousNode.isBoolean() || !confidenceNode.isNumber()
                    || !reasonNode.isTextual() || !actionsNode.isArray()) {
                logger.warn("LLM JSON contains invalid field types");
                return null;
            }

            double confidence = confidenceNode.asDouble();
            if (!Double.isFinite(confidence) || confidence < 0.0 || confidence > 1.0) {
                logger.warn("Invalid confidence: {}", confidence);
                return null;
            }

            List<String> actions = parseActions(actionsNode);
            if (actions.size() != 1) {
                logger.warn("LLM must return exactly one action");
                return null;
            }

            String reason = reasonNode.asText("").trim();
            if (reason.length() > MAX_REASON_LENGTH) {
                reason = reason.substring(0, MAX_REASON_LENGTH);
            }

            return new AnalysisResult(suspiciousNode.asBoolean(), confidence, reason, actions);

        } catch (IOException e) {
            logger.error(LocaleUtil.getString("llm_client_json_parse_error"), e.getMessage());
            return null;
        } catch (RuntimeException e) {
            logger.error(LocaleUtil.getString("llm_client_parse_error"), e.getMessage());
            return null;
        }
    }

    private static String extractJsonFromMarkdown(String content) {
        if (content == null || content.isBlank()) {
            return content;
        }

        String trimmed = content.trim();

        if (trimmed.startsWith("```")) {
            Matcher matcher = JSON_PATTERN.matcher(trimmed);
            if (matcher.find()) {
                return matcher.group(1);
            }

            int startIndex = trimmed.indexOf('{');
            int endIndex = trimmed.lastIndexOf('}');
            if (startIndex >= 0 && endIndex > startIndex) {
                return trimmed.substring(startIndex, endIndex + 1);
            }
        }

        return trimmed;
    }

    private List<String> parseActions(JsonNode actionsNode) {
        List<String> result = new ArrayList<>();

        for (JsonNode actionNode : actionsNode) {
            if (!actionNode.isTextual()) {
                continue;
            }

            String action = actionNode.asText("").trim();
            if ("BLOCK_DOMAIN".equals(action) || "BLOCK_REQUEST".equals(action)
                    || "LOG_ONLY".equals(action) || "NONE".equals(action)) {
                result.add(action);
            }
        }

        return result.isEmpty() ? Collections.emptyList() : Collections.unmodifiableList(result);
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