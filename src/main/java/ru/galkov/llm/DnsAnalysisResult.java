package ru.galkov.llm;

import java.util.Collections;
import java.util.List;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class DnsAnalysisResult {
    private final boolean isSuspicious;
    private final double confidence;
    private final String reason;
    private final List<String> recommendedActions;

    public DnsAnalysisResult(boolean isSuspicious, double confidence, String reason, List<String> recommendedActions) {
        this.isSuspicious = isSuspicious;
        this.confidence = confidence;
        this.reason = reason;
        this.recommendedActions = recommendedActions != null ? Collections.unmodifiableList(recommendedActions) : Collections.emptyList();
    }

    public boolean isSuspicious() {
        return isSuspicious;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getReason() {
        return reason;
    }
}