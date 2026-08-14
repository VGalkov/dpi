package ru.galkov.llm;

import java.util.Collections;
import java.util.List;

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

    public List<String> getRecommendedActions() {
        return recommendedActions;
    }
}