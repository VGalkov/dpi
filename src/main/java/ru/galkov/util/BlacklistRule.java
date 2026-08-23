package ru.galkov.util;

import java.util.Locale;
import java.util.Objects;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public record BlacklistRule(RuleType type, String value, String source, String sourceRecordId, String blockType) {
    public enum RuleType {DOMAIN, IP, URL}

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        BlacklistRule that = (BlacklistRule) obj;
        return type == that.type && Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        int result = type != null ? type.hashCode() : 0;
        result = 31 * result + (value != null ? value.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "BlacklistRule{type=%s, value='%s', source='%s'}", type, value, source);
    }
}