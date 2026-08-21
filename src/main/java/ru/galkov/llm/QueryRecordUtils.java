package ru.galkov.llm;

import java.util.Locale;

/**
 * Утилиты для QueryRecord классов.
 * s0506777@yandex.ru Galkov V.A.
 */
public final class QueryRecordUtils {

    private QueryRecordUtils() {}

    // ✅ Нормализация
    public static String normalize(String value) {
        return value == null ? "" : value.trim();
    }

    public static String normalizeNullable(String value) {
        if (value == null) return null;
        String result = value.trim();
        return result.isEmpty() ? null : result;
    }

    public static String normalizeDomain(String value) {
        if (value == null) return null;
        String result = value.trim().toLowerCase(Locale.ROOT);
        while (result.endsWith(".")) {
            result = result.substring(0, result.length() - 1);
        }
        return result.isEmpty() ? null : result;
    }

    public static String normalizeHost(String value) {
        String host = normalize(value).toLowerCase(Locale.ROOT);
        while (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        return host;
    }

    // ✅ Проверка IP
    public static boolean isIpLiteral(String value) {
        if (value.isEmpty()) return false;
        return value.indexOf(':') >= 0 ? isIpv6Literal(value) : isIpv4Literal(value);
    }

    public static boolean isIpv4Literal(String value) {
        int dots = 0, lastDot = -1;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '.') {
                if (++dots > 3 || i - lastDot - 1 > 3) return false;
                lastDot = i;
            } else if (c < '0' || c > '9') {
                return false;
            }
        }
        if (dots != 3) return false;
        for (String part : value.split("\\.")) {
            if (part.isEmpty()) return false;
            try {
                int n = Integer.parseInt(part);
                if (n < 0 || n > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    public static boolean isIpv6Literal(String value) {
        if (value.isEmpty()) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c == ':' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    // ✅ Метрики
    public static double calculateDigitRatio(String value) {
        if (value == null || value.isEmpty()) return 0.0;
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (Character.isDigit(value.charAt(i))) count++;
        }
        return (double) count / value.length();
    }

    public static double calculateHyphenRatio(String value) {
        if (value == null || value.isEmpty()) return 0.0;
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '-') count++;
        }
        return (double) count / value.length();
    }

    // ✅ Ограничение длины
    public static String limit(String value, int maxLength) {
        if (value.length() <= maxLength) return value;
        return value.substring(0, maxLength);
    }

    // ✅ Расчёт энтропии (только для DNS)
    public static double calculateEntropy(String value) {
        if (value == null || value.isEmpty()) return 0.0;
        double LOG_2 = Math.log(2.0);
        int[] frequency = new int[Character.MAX_VALUE + 1];
        int length = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '.') continue;
            frequency[c]++;
            length++;
        }
        if (length == 0) return 0.0;
        double result = 0.0;
        for (int count : frequency) {
            if (count == 0) continue;
            double probability = (double) count / length;
            result -= probability * Math.log(probability) / LOG_2;
        }
        return result;
    }

    // ✅ Подсчёт точек (только для DNS)
    public static int countDots(String value) {
        if (value == null || value.isEmpty()) return 0;
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') count++;
        }
        return count;
    }

    // ✅ Parent domain (только для DNS)
    public static String calculateParentDomain(String value) {
        if (value == null || value.isEmpty()) return "";
        int index = value.indexOf('.');
        if (index < 0 || index == value.length() - 1) return value;
        return value.substring(index + 1);
    }

    // ✅ Leftmost label (только для DNS)
    public static String calculateLeftmostLabel(String value) {
        if (value == null || value.isEmpty()) return "";
        int index = value.indexOf('.');
        return index < 0 ? value : value.substring(0, index);
    }

    // ✅ Max label length (только для DNS)
    public static int calculateMaxLabelLength(String value) {
        if (value == null || value.isEmpty()) return 0;
        int max = 0, current = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') {
                if (current > max) max = current;
                current = 0;
            } else {
                current++;
            }
        }
        return Math.max(max, current);
    }

    // ✅ Unique character ratio (только для DNS)
    public static double calculateUniqueCharacterRatio(String value) {
        if (value == null || value.isEmpty()) return 0.0;
        boolean[] seen = new boolean[Character.MAX_VALUE + 1];
        int unique = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!seen[c]) {
                seen[c] = true;
                unique++;
            }
        }
        return (double) unique / value.length();
    }

    // ✅ Base32-like (только для DNS)
    public static boolean isBase32Like(String value) {
        if (value == null || value.length() < 12) return false;
        int valid = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = Character.toUpperCase(value.charAt(i));
            if ((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) valid++;
        }
        return (double) valid / value.length() >= 0.95;
    }

    // ✅ Base64-like (только для DNS)
    public static boolean isBase64Like(String value) {
        if (value == null || value.length() < 16) return false;
        int valid = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
                valid++;
            }
        }
        return (double) valid / value.length() >= 0.95;
    }

    // ✅ Punycode (только для DNS)
    public static boolean containsPunycode(String value) {
        if (value == null || value.isEmpty()) return false;
        for (String label : value.split("\\.")) {
            if (label.startsWith("xn--")) return true;
        }
        return false;
    }

    // ✅ IP-like label (только для DNS)
    public static boolean containsIpLikeLabel(String value) {
        if (value == null || value.isEmpty()) return false;
        for (String label : value.split("\\.")) {
            int digits = 0, hyphens = 0;
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (Character.isDigit(c)) digits++;
                else if (c == '-') hyphens++;
            }
            if (digits >= 4 && hyphens >= 1) return true;
        }
        return false;
    }

    // ✅ Suspicious keyword (только для DNS)
    public static boolean containsSuspiciousKeyword(String value) {
        if (value == null || value.isEmpty()) return false;
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.contains("malware") || lower.contains("phishing") ||
                lower.contains("exploit") || lower.contains("ransom") ||
                lower.contains("botnet") || lower.contains("keylogger") ||
                lower.contains("stealer");
    }

    // ✅ Suspicious TLD (только для HTTP)
    public static boolean hasSuspiciousTld(String host) {
        return host.endsWith(".xyz") || host.endsWith(".top") ||
                host.endsWith(".tk") || host.endsWith(".club") ||
                host.endsWith(".work");
    }

    // ✅ Path traversal (только для HTTP)
    public static boolean hasPathTraversal(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.contains("../") || lower.contains("..\\") ||
                lower.contains("%2e%2e") || lower.contains("2e2e2f") ||
                lower.contains("2e2e5c");
    }

    // ✅ Injection markers (только для HTTP)
    public static boolean hasInjectionMarkers(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.contains("select ") || lower.contains(" union ") ||
                lower.contains(" drop ") || lower.contains(" insert ") ||
                lower.contains(" update ") || lower.contains(" delete ") ||
                lower.contains(" or 1=1") || lower.contains("<script") ||
                lower.contains("javascript:") || lower.contains("onerror=") ||
                lower.contains("onload=") || lower.contains("$(") ||
                lower.contains(";%00") || lower.contains("%0a") ||
                lower.contains("%0d") || lower.contains("../") ||
                lower.contains("..\\");
    }

    // ✅ Suspicious User-Agent (только для HTTP)
    public static boolean hasSuspiciousUserAgent(String headers) {
        String lower = headers.toLowerCase(Locale.ROOT);
        return lower.contains("user-agent: curl") ||
                lower.contains("user-agent: wget") ||
                lower.contains("user-agent: python") ||
                lower.contains("user-agent: nikto") ||
                lower.contains("user-agent: sqlmap") ||
                lower.contains("user-agent: nmap");
    }
}