package ru.galkov.util;

public final class LogFields {

    private LogFields() {
    }

    public static String kv(String key, Object value) {
        if (value == null)
            return key + "=null";

        String s = value.toString();

        // экранирование пробелов и кавычек не делаем, пока достаточно простого формата
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