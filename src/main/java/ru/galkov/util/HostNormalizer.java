package ru.galkov.util;

import java.net.InetAddress;
import java.util.Locale;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class HostNormalizer {

    private HostNormalizer() {
    }

    public static String normalizeHost(String value) {
        if (value == null || value.trim().isEmpty()) return null;
        String host = value.trim().toLowerCase(Locale.ROOT);
        host = removeTrailingDot(host);
        if (host.isEmpty()) return null;
        if (host.indexOf(':') >= 0) return null;
        if (host.indexOf(' ') >= 0 || host.indexOf('/') >= 0) return null;
        return host;
    }

    public static String normalizeIp(String value) {
        if (value == null || value.trim().isEmpty()) return null;
        String ip = value.trim();
        if (ip.indexOf('/') >= 0) return null;
        if (!isIpLiteralFast(ip)) return null;
        try {
            return InetAddress.getByName(ip).getHostAddress().toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }

    public static String removeTrailingDot(String value) {
        if (value == null) return null;
        String result = value;
        while (result.endsWith(".")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    public static String normalizeDomain(String domain) {
        if (domain == null) return null;
        String normalized = domain.trim().toLowerCase(Locale.ROOT);
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.isEmpty() ? null : normalized;
    }

    public static String[] splitHostToLabels(String domain) {
        if (domain == null || domain.isEmpty()) return new String[0];
        int dots = 0;
        for (int i = 0; i < domain.length(); i++) {
            if (domain.charAt(i) == '.') dots++;
        }
        if (dots == 0) return new String[]{domain};
        String[] labels = new String[dots + 1];
        int start = 0, index = 0;
        for (int i = 0; i <= domain.length(); i++) {
            if (i == domain.length() || domain.charAt(i) == '.') {
                labels[index++] = domain.substring(start, i);
                start = i + 1;
            }
        }
        return labels;
    }

    public static HostAndPort parseHostPort(String value) {
        if (value == null || value.isEmpty()) return null;
        String host, portText;
        if (value.startsWith("[")) {
            int close = value.indexOf(']');
            if (close <= 1 || close + 1 >= value.length() || value.charAt(close + 1) != ':') return null;
            host = value.substring(1, close);
            portText = value.substring(close + 2);
        } else {
            int colon = value.lastIndexOf(':');
            if (colon <= 0 || colon == value.length() - 1) return null;
            host = value.substring(0, colon);
            portText = value.substring(colon + 1);
            if (host.indexOf(':') >= 0) return null;
        }
        int port;
        try {
            port = Integer.parseInt(portText);
        } catch (NumberFormatException e) {
            return null;
        }
        if (port < 1 || port > 65535) return null;
        return new HostAndPort(host, port);
    }

    public static boolean isIpLiteralFast(String value) {
        if (value == null || value.isEmpty()) return false;
        if (value.indexOf(':') >= 0) return isIpv6LiteralFast(value);
        int len = value.length(), dots = 0, lastDot = -1;
        for (int i = 0; i < len; i++) {
            char c = value.charAt(i);
            if (c == '.') {
                if (++dots > 3 || i - lastDot - 1 > 3) return false;
                lastDot = i;
            } else if (c < '0' || c > '9') {
                return false;
            }
        }
        if (dots != 3) return false;
        int start = 0;
        for (int i = 0; i <= len; i++) {
            if (i == len || value.charAt(i) == '.') {
                if (i - start > 3) return false;
                try {
                    int n = Integer.parseInt(value.substring(start, i));
                    if (n < 0 || n > 255) return false;
                } catch (NumberFormatException e) {
                    return false;
                }
                start = i + 1;
            }
        }
        return true;
    }

    public static boolean isIpv6LiteralFast(String value) {
        if (value == null || value.isEmpty()) return false;
        int len = value.length();
        for (int i = 0; i < len; i++) {
            char c = value.charAt(i);
            if (!(c == ':' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    public record HostAndPort(String host, int port) {
    }
}