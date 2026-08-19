package ru.galkov.util;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public record BlacklistRule(RuleType type, String value, String source, String sourceRecordId, String blockType) {
    public enum RuleType {DOMAIN, IP, URL}

    @Override
    public String toString() {
        return "BlacklistRule{type=" + type + ", value=" + value + ", source=" + source + "}";
    }
}