package ru.galkov.llm;

import java.util.Collections;
import java.util.List;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * Результат анализа аномалии (DNS или HTTP) через LLM Studio.
 */
public record AnalysisResult(boolean suspicious, double confidence, String reason, List<String> recommendedActions) {
    public AnalysisResult(boolean suspicious, double confidence, String reason, List<String> recommendedActions) {
        this.suspicious = suspicious;
        this.confidence = confidence;
        this.reason = reason;
        this.recommendedActions = recommendedActions != null
                ? Collections.unmodifiableList(recommendedActions)
                : Collections.emptyList();
    }

    @Override
    public String toString() {
        return "AnalysisResult{suspicious=" + suspicious
                + ", confidence=" + confidence
                + ", reason='" + reason + '\''
                + ", actions=" + recommendedActions.size() + '}';
    }
}