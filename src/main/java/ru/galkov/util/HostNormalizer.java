package ru.galkov.util;

import java.util.Locale;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class HostNormalizer {
    private static final int IPV4_LENGTH = 4;
    private static final int IPV6_LENGTH = 16;

    private HostNormalizer() {
    }

    public static String normalizeHost(String value) {
        if (value == null || value.trim().isEmpty()) return null;
        String host = value.trim().toLowerCase(Locale.ROOT);
        host = removeTrailingDot(host);
        if (host == null || host.isEmpty()) return null;


        if (
                host.length() > 253
                        || host.startsWith(".")
                        || host.endsWith(".")
                        || host.indexOf(':') >= 0
                        || host.indexOf('/') >= 0
                        || host.indexOf(' ') >= 0
                        || host.indexOf('\\') >= 0
        ) {
            return null;
        }

        String[] labels = splitHostToLabels(host);

        for (String label : labels) {
            if (!isValidDnsLabel(label)) return null;
        }

        return host;
    }

    public static String normalizeIp(String value) {
        if (value == null || value.trim().isEmpty()) return null;
        String ip = value.trim();
        if (
                ip.indexOf('/') >= 0
                        || ip.indexOf('%') >= 0
                        || ip.indexOf(' ') >= 0
                        || ip.indexOf('\\') >= 0
                        || ip.indexOf('[') >= 0
                        || ip.indexOf(']') >= 0
        ) {
            return null;
        }

        if (ip.indexOf(':') >= 0) {
            byte[] ipv6 = parseIpv6Literal(ip);
            return ipv6 == null ? null : formatIpv6(ipv6);
        }

        byte[] ipv4 = parseIpv4Literal(ip);
        return ipv4 == null ? null : formatIpv4(ipv4);
    }

    public static byte[] parseIpLiteral(String value) {
        if (value == null || value.isEmpty()) return null;
        if (value.indexOf(':') >= 0) return parseIpv6Literal(value);
        return parseIpv4Literal(value);
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
        normalized = removeTrailingDot(normalized);
        return normalized == null || normalized.isEmpty() ? null : normalized;
    }

    public static String[] splitHostToLabels(String domain) {
        if (domain == null || domain.isEmpty()) return new String[0];
        int dots = 0;

        for (int i = 0; i < domain.length(); i++) {
            if (domain.charAt(i) == '.') dots++;
        }

        if (dots == 0) return new String[]{domain};
        String[] labels = new String[dots + 1];
        int start = 0;
        int index = 0;

        for (int i = 0; i <= domain.length(); i++) {
            if (i == domain.length() || domain.charAt(i) == '.') {
                labels[index++] = domain.substring(start, i);
                start = i + 1;
            }
        }

        return labels;
    }

    public static HostAndPort parseHostPort(String value) {
        if (value == null || value.trim().isEmpty()) return null;

        String input = value.trim();
        String host;
        String portText;
        if (input.startsWith("[")) {
            int close = input.indexOf(']');
            if (close <= 1 || close + 1 >= input.length() || input.charAt(close + 1) != ':')
                return null;
            host = input.substring(1, close);
            portText = input.substring(close + 2);
        } else {
            int colon = input.lastIndexOf(':');

            if (colon <= 0 || colon == input.length() - 1 || input.substring(0, colon).indexOf(':') >= 0)
                return null;

            host = input.substring(0, colon);
            portText = input.substring(colon + 1);
        }

        int port;

        try {
            port = Integer.parseInt(portText);
        } catch (NumberFormatException e) {
            return null;
        }

        if (port < 1 || port > 65535) return null;

        String normalizedHost = normalizeIp(host);
        if (normalizedHost == null) normalizedHost = normalizeHost(host);
        return normalizedHost == null ? null : new HostAndPort(normalizedHost, port);
    }

    public static boolean isIpLiteralFast(String value) {
        return parseIpLiteral(value) != null;
    }

    public static boolean isIpv6LiteralFast(String value) {
        return value != null && value.indexOf(':') >= 0 && parseIpv6Literal(value) != null;
    }

    private static byte[] parseIpv4Literal(String value) {
        if (value == null || value.isEmpty()) return null;

        byte[] result = new byte[IPV4_LENGTH];
        int start = 0;

        for (int part = 0; part < IPV4_LENGTH; part++) {
            int end = value.indexOf('.', start);
            if (end < 0) end = value.length();


            if (end <= start || end - start > 3) return null;
            String segment = value.substring(start, end);
            if (segment.length() > 1 && segment.charAt(0) == '0') return null;
            int number = 0;

            for (int i = 0; i < segment.length(); i++) {
                char c = segment.charAt(i);
                if (c < '0' || c > '9') return null;
                number = number * 10 + c - '0';
                if (number > 255) return null;

            }

            result[part] = (byte) number;
            start = end + 1;
        }

        return start == value.length() + 1 ? result : null;
    }

    private static byte[] parseIpv6Literal(String value) {
        if (
                value == null
                        || value.isEmpty()
                        || value.indexOf('%') >= 0
                        || value.indexOf('[') >= 0
                        || value.indexOf(']') >= 0
        ) {
            return null;
        }

        int doubleColon = value.indexOf("::");

        if (doubleColon >= 0 && value.indexOf("::", doubleColon + 2) >= 0)
            return null;

        String left = doubleColon >= 0 ? value.substring(0, doubleColon) : value;
        String right = doubleColon >= 0 ? value.substring(doubleColon + 2) : "";
        int leftGroups = countIpv6Groups(left);
        int rightGroups = countIpv6Groups(right);

        if (leftGroups < 0 || rightGroups < 0) return null;
        int totalGroups = leftGroups + rightGroups;

        if (doubleColon < 0) {
            if (totalGroups != 8) return null;
        } else if (totalGroups >= 8) {
            return null;
        }

        byte[] result = new byte[IPV6_LENGTH];
        int position = 0;
        position = writeIpv6Groups(left, result, position);

        if (doubleColon >= 0) {
            int zeroGroups = 8 - totalGroups;
            position += zeroGroups * 2;
        }

        position = writeIpv6Groups(right, result, position);

        return position == IPV6_LENGTH ? result : null;
    }

    private static String formatIpv4(byte[] bytes) {
        if (bytes == null || bytes.length != IPV4_LENGTH)
            return null;

        return ((bytes[0] & 0xff) + "." + (bytes[1] & 0xff) + "." + (bytes[2] & 0xff) + "." + (bytes[3] & 0xff));
    }

    private static String formatIpv6(byte[] bytes) {
        if (bytes == null || bytes.length != IPV6_LENGTH) return null;
        int[] groups = new int[8];

        for (int i = 0; i < groups.length; i++)
            groups[i] = ((bytes[i * 2] & 0xff) << 8) | (bytes[i * 2 + 1] & 0xff);

        int bestStart = -1;
        int bestLength = 0;

        for (int i = 0; i < groups.length; ) {
            if (groups[i] != 0) {
                i++;
                continue;
            }

            int start = i;
            while (i < groups.length && groups[i] == 0) {
                i++;
            }

            int length = i - start;

            if (length >= 2 && length > bestLength) {
                bestStart = start;
                bestLength = length;
            }
        }

        StringBuilder result = new StringBuilder(39);
        int index = 0;

        while (index < groups.length) {
            if (index == bestStart) {
                result.append("::");
                index += bestLength;
                continue;
            }

            if (index > 0 && index != bestStart + bestLength) result.append(':');

            result.append(Integer.toHexString(groups[index]));
            index++;
        }

        return result.toString();
    }

    private static int countIpv6Groups(String part) {
        if (part.isEmpty()) {
            return 0;
        }

        String[] groups = part.split(":", -1);
        int count = 0;

        for (int i = 0; i < groups.length; i++) {
            String group = groups[i];
            if (group.isEmpty()) return -1;
            if (group.indexOf('.') >= 0) {
                if (i != groups.length - 1 || parseIpv4Literal(group) == null) return -1;
                count += 2;
            } else {
                if (group.length() > 4)
                    return -1;
                for (int j = 0; j < group.length(); j++) {
                    if (Character.digit(group.charAt(j), 16) < 0) return -1;
                }

                count++;
            }
        }

        return count;
    }

    private static int writeIpv6Groups(String part, byte[] target, int position) {
        if (part.isEmpty()) return position;
        String[] groups = part.split(":", -1);

        for (String group : groups) {
            if (group.indexOf('.') >= 0) {
                byte[] ipv4 = parseIpv4Literal(group);
                target[position++] = ipv4[0];
                target[position++] = ipv4[1];
                target[position++] = ipv4[2];
                target[position++] = ipv4[3];
            } else {
                int number = Integer.parseInt(group, 16);
                target[position++] = (byte) (number >>> 8);
                target[position++] = (byte) number;
            }
        }

        return position;
    }

    private static boolean isValidDnsLabel(String label) {
        if (
                label == null
                        || label.isEmpty()
                        || label.length() > 63
                        || label.charAt(0) == '-'
                        || label.charAt(
                        label.length() - 1
                ) == '-'
        ) {
            return false;
        }

        for (int i = 0; i < label.length(); i++) {
            char c = label.charAt(i);
            if (!(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-')) return false;
        }

        return true;
    }

    public record HostAndPort(String host, int port) { }
}