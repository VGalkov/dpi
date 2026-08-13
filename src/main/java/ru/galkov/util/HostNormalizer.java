package ru.galkov.util;

import java.net.InetAddress;
import java.util.Locale;

public final class HostNormalizer {

    private HostNormalizer() {
    }

    public static String normalizeHost(String value) {

        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        String host = value.trim().toLowerCase(Locale.ROOT);

        host = removeTrailingDot(host);

        if (host.isEmpty()) {
            return null;
        }

        if (host.indexOf(':') >= 0) {
            return null;
        }

        if (host.indexOf(' ') >= 0 || host.indexOf('/') >= 0) {
            return null;
        }

        return host;
    }

    public static String normalizeIp(String value) {

        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        String ip = value.trim();

        if (ip.indexOf('/') >= 0) {
            return null;
        }

        if (!looksLikeIp(ip)) {
            return null;
        }

        try {
            return InetAddress.getByName(ip).getHostAddress().toLowerCase(Locale.ROOT);

        } catch (Exception e) {
            return null;
        }
    }

    public static String removeTrailingDot(String value) {

        if (value == null) {
            return null;
        }

        String result = value;

        while (result.endsWith(".")) {
            result = result.substring(0, result.length() - 1);
        }

        return result;
    }

    private static boolean looksLikeIp(String value) {

        if (value.indexOf(':') >= 0) {
            return true;
        }

        String[] parts = value.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty()) {
                return false;
            }

            for (int i = 0; i < part.length(); i++) {

                if (!Character.isDigit(part.charAt(i))) {
                    return false;
                }
            }

            try {
                int number = Integer.parseInt(part);

                if (number < 0 || number > 255) {
                    return false;
                }

            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }
}