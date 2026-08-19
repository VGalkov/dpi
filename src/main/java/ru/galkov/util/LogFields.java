package ru.galkov.util;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class LogFields {
    private LogFields() {}

    /**
     * ✅ П.29: Компактный метод без String.format
     */
    public static String kv(String key, Object value) {
        return key + '=' + (value != null ? value : "null");
    }
}