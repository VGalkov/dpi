package ru.galkov.llm;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public interface AnomalyStrategy<T extends AbstractQueryRecord> {
    String buildPrompt(T record);
    void logAnomaly(T record, AnalysisResult result);
    String getConfigPrefix();
}