package ru.galkov.util;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class LogFields {

    private LogFields() {
    }

    public static String kv(String key, Object value) {
        if (value == null)
            return key + "=null";

        String s = value.toString();

        return key + "=" + s;
    }

    public static String kv(String key, String value) {
        if (value == null)
            return key + "=null";
        return key + "=" + value;
    }

    public static String kv(String key, int value) {
        return key + "=" + value;
    }

    public static String kv(String key, long value) {
        return key + "=" + value;
    }

}