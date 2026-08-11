package ru.galkov.servers;

import java.net.InetAddress;
import java.util.Locale;

public final class HostNormalizer {

    private HostNormalizer() {
        // Запрещаем создание экземпляров
    }

    public static String normalizeHost(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        String host = value.trim()
                .toLowerCase(Locale.ROOT);

        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }

        if (host.isEmpty()) {
            return null;
        }

        if (host.contains(":")) {
            return null;
        }

        return host;
    }

    public static String normalizeIp(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        String ip = value.trim();

        int slash = ip.indexOf('/');
        if (slash >= 0) {
            ip = ip.substring(0, slash);
        }

        if (!looksLikeIp(ip)) {
            return null;
        }

        try {
            return InetAddress.getByName(ip)
                    .getHostAddress()
                    .toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean looksLikeIp(String value) {
        return value.contains(".") || value.contains(":");
    }
}