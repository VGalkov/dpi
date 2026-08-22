package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * Стратегия для HTTP-аномалий.
 */
public class HttpAnomalyStrategy implements AnomalyStrategy<HttpQueryRecord> {
    private static final Logger logger = LoggerFactory.getLogger(HttpAnomalyStrategy.class);
    private final String promptTemplate;
    private final String configPrefix;
    private final boolean inspectBody;
    private final int bodyPreviewLength;

    public HttpAnomalyStrategy(String configPrefix, boolean inspectBody, int bodyPreviewLength) {
        this.configPrefix = configPrefix;
        this.inspectBody = inspectBody;
        this.bodyPreviewLength = bodyPreviewLength;
        this.promptTemplate = loadPromptTemplate("prompts/http_anomaly_prompt.txt");
    }

    @Override
    public String buildPrompt(HttpQueryRecord record) {
        String bodyPreview = "";
        if (inspectBody && !record.getBody().isEmpty()) {
            bodyPreview = record.getBody();
            if (bodyPreview.length() > bodyPreviewLength)
                bodyPreview = bodyPreview.substring(0, bodyPreviewLength);
        }
        if (promptTemplate == null || promptTemplate.isBlank()) return "";
        return promptTemplate
                .replace("{clientIp}", promptValue(record.getClientIp(), 128))
                .replace("{method}", promptValue(record.getMethod(), 32))
                .replace("{host}", promptValue(record.getHost(), 253))
                .replace("{port}", String.valueOf(record.getPort()))
                .replace("{path}", promptValue(record.getPath(), 4096))
                .replace("{headers}", promptValue(record.getHeaders(), 8192))
                .replace("{bodyPreview}", promptValue(bodyPreview, bodyPreviewLength))
                .replace("{timestamp}", String.valueOf(record.getTimestamp()))
                .replace("{pathLength}", String.valueOf(record.getPathLength()))
                .replace("{headerLength}", String.valueOf(record.getHeaderLength()))
                .replace("{bodyLength}", String.valueOf(record.getBodyLength()))
                .replace("{https}", String.valueOf(record.isHttps()))
                .replace("{hostIsIp}", String.valueOf(record.isHostIp()))
                .replace("{suspiciousTld}", String.valueOf(record.hasSuspiciousTld()))
                .replace("{pathHasTraversal}", String.valueOf(record.hasPathTraversal()))
                .replace("{pathHasInjectionMarkers}", String.valueOf(record.hasPathInjectionMarkers()))
                .replace("{bodyHasInjectionMarkers}", String.valueOf(record.hasBodyInjectionMarkers()))
                .replace("{suspiciousUserAgent}", String.valueOf(record.hasSuspiciousUserAgent()));
    }

    @Override
    public void logAnomaly(HttpQueryRecord record, AnalysisResult result) {
        logger.info("HTTP anomaly detected: client={}, method={}, host={}, path={}, confidence={}, reason={}, actions={}",
                record.getClientIp(), record.getMethod(), record.getHost(), record.getPath(),
                result.confidence(), result.reason(), result.recommendedActions());
    }

    @Override
    public String getConfigPrefix() { return configPrefix; }

    private String promptValue(String value, int maxLength) {
        String sanitized = LlmAnomalyDetector.sanitizeForPrompt(value, maxLength);
        return sanitized.isEmpty() ? "unknown" : sanitized;
    }

    private String loadPromptTemplate(String resourceName) {
        try (var input = getClass().getClassLoader().getResourceAsStream(resourceName)) {
            if (input == null) {
                logger.warn("Prompt template not found: {}", resourceName);
                return "";
            }
            return new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Prompt template loading failed: {}", resourceName, e);
            return "";
        }
    }
}