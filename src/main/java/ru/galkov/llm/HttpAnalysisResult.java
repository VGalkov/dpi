package ru.galkov.llm;

import java.util.Collections;
import java.util.List;

/**
 * Результат проверки HTTP/HTTPS-запроса через LLM Studio.
 */
public final class HttpAnalysisResult {

    private final boolean suspicious;
    private final double confidence;
    private final String reason;
    private final List<String> recommendedActions;

    public HttpAnalysisResult(boolean suspicious,
                              double confidence,
                              String reason,
                              List<String> recommendedActions) {
        this.suspicious = suspicious;
        this.confidence = confidence;
        this.reason = reason;
        this.recommendedActions = recommendedActions == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(recommendedActions);
    }

    public boolean isSuspicious() {
        return suspicious;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getReason() {
        return reason;
    }

    public List<String> getRecommendedActions() {
        return recommendedActions;
    }
}