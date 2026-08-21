package ru.galkov.llm;

import ru.galkov.util.BlacklistSnapshot;

import java.util.List;
import java.util.Locale;

/**
 * Абстрактный базовый класс для записей запросов.
 * s0506777@yandex.ru Galkov V.A.
 */
public abstract class AbstractQueryRecord {

    protected final String clientIp;
    protected final long timestamp;

    protected AbstractQueryRecord(String clientIp, long timestamp) {
        this.clientIp = normalizeNullable(clientIp);
        this.timestamp = timestamp;
    }

    public String getClientIp() {
        return clientIp;
    }

    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Проверяет, является ли целевой хост/IP заблокированным.
     */
    public boolean isBlocked(BlacklistSnapshot snapshot) {
        if (snapshot == null) return false;

        if (snapshot.checkIp(clientIp).isBlocked()) return true;

        String target = getTarget();
        if (target == null || target.isEmpty()) return false;

        return snapshot.checkDomain(target).isBlocked();
    }

    /**
     * Целевой домен/хост запроса.
     */
    public abstract String getTarget();

    /**
     * Длина целевого домена/хоста.
     */
    public abstract int getTargetLength();

    /**
     * Является ли хост IP-адресом.
     */
    public abstract boolean isTargetIp();

    /**
     * Подозрительный TLD.
     */
    public abstract boolean hasSuspiciousTld();

    /**
     * Признаки инъекций.
     */
    public abstract boolean hasInjectionMarkers();

    /**
     * Подозрительный индикатор.
     */
    public abstract boolean hasSuspiciousIndicator();

    /**
     * Краткое описание для логирования.
     */
    protected String buildBaseToString() {
        return "clientIp='" + clientIp + "', timestamp=" + timestamp;
    }

    // ✅ Пункт 1: Универсальный метод нормализации
    public static String normalize(String value) {
        return value == null ? "" : value.trim();
    }

    public static String normalizeNullable(String value) {
        if (value == null) return null;
        String result = value.trim();
        return result.isEmpty() ? null : result;
    }

    public static String normalizeDomain(String value) {
        return normalize(value, true, true);
    }

    public static String normalizeHost(String value) {
        return normalize(value, true, true);
    }

    // ✅ Универсальный метод нормализации (вместо 4 дублирующихся)
    public static String normalize(String value, boolean toLowerCase, boolean removeTrailingDots) {
        if (value == null) return null;
        String result = value.trim();
        if (toLowerCase) result = result.toLowerCase(Locale.ROOT);
        if (removeTrailingDots) {
            while (result.endsWith(".")) {
                result = result.substring(0, result.length() - 1);
            }
        }
        return result.isEmpty() ? null : result;
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

    // ✅ Пункт 2: Универсальный метод для расчёта ratio символов
    public static double calculateDigitRatio(String value) {
        if (value == null || value.isEmpty()) return 0.0;
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (Character.isDigit(value.charAt(i))) count++;
        }
        return (double) count / value.length();
    }

    public static double calculateHyphenRatio(String value) {
        return calculateCharRatio(value, '-');
    }

    // ✅ Универсальный метод для расчёта ratio (вместо дублирования)
    public static double calculateCharRatio(String value, char target) {
        if (value == null || value.isEmpty()) return 0.0;
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == target) count++;
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

    // ✅ Пункт 3: Универсальный метод для Base32/Base64-like проверки
    public static boolean isBase32Like(String value) {
        return isLikeEncoding(value, c -> {
            char upper = Character.toUpperCase(c);
            return (upper >= 'A' && upper <= 'Z') || (upper >= '2' && upper <= '7');
        }, 12);
    }

    public static boolean isBase64Like(String value) {
        return isLikeEncoding(value, c ->
                        (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=',
                16
        );
    }

    // ✅ Универсальный метод для Base32/Base64-like (вместо дублирования)
    public static boolean isLikeEncoding(String value, java.util.function.Predicate<Character> validator, int minLength) {
        if (value == null || value.length() < minLength) return false;
        int valid = 0;
        for (int i = 0; i < value.length(); i++) {
            if (validator.test(value.charAt(i))) valid++;
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

    // ✅ Пункт 4: Оптимизация через список маркеров (вместо 20+ проверок)
    private static final List<String> INJECTION_MARKERS = List.of(
            "select ", " union ", " drop ", " insert ", " update ", " delete ",
            " or 1=1", "<script", "javascript:", "onerror=", "onload=",
            "$(", ";%00", "%0a", "%0d", "../", "..\\"
    );

    public static boolean hasInjectionMarkers(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return INJECTION_MARKERS.stream().anyMatch(lower::contains);
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