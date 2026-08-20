package ru.galkov.util;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class RuleNormalizer {
    private RuleNormalizer() {}

    public static String normalizeRule(String line) {
        if (line == null)
            return null;

        String value = line.trim();
        if (value.isEmpty() || value.startsWith("#") || value.startsWith("!"))
            return null;

        int commentIndex = value.indexOf('#');
        if (commentIndex >= 0)
            value = value.substring(0, commentIndex).trim();

        return value.isEmpty() ? null : value;
    }
}