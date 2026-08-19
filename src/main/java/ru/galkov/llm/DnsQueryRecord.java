package ru.galkov.llm;

import java.util.Locale;

public final class DnsQueryRecord {
    private static final double LOG_2 = Math.log(2.0);

    private final String clientIp;
    private final String domain;
    private final int queryType;
    private final long timestamp;
    private final boolean query;
    private final int opcode;
    private final boolean truncated;
    private final boolean recursionDesired;
    private final int z;
    private final int rcode;

    private final int domainLength;
    private final double entropy;
    private final int subdomainCount;
    private final String parentDomain;
    private final String leftmostLabel;
    private final int leftmostLabelLength;
    private final int maxLabelLength;
    private final double digitRatio;
    private final double hyphenRatio;
    private final double uniqueCharacterRatio;
    private final boolean base32Like;
    private final boolean base64Like;
    private final boolean punycode;
    private final boolean ipLikeLabel;
    private final boolean suspiciousKeyword;

    public DnsQueryRecord(
            String clientIp,
            String domain,
            int queryType,
            long timestamp,
            boolean query,
            int opcode,
            boolean truncated,
            boolean recursionDesired,
            int z,
            int rcode
    ) {
        this.clientIp = normalizeNullable(clientIp);
        this.domain = normalizeDomain(domain);
        this.queryType = queryType;
        this.timestamp = timestamp;
        this.query = query;
        this.opcode = opcode;
        this.truncated = truncated;
        this.recursionDesired = recursionDesired;
        this.z = z;
        this.rcode = rcode;

        this.domainLength = this.domain == null ? 0 : this.domain.length();
        this.entropy = calculateEntropy(this.domain);
        this.subdomainCount = countDots(this.domain);
        this.parentDomain = calculateParentDomain(this.domain);
        this.leftmostLabel = calculateLeftmostLabel(this.domain);
        this.leftmostLabelLength = this.leftmostLabel.length();
        this.maxLabelLength = calculateMaxLabelLength(this.domain);
        this.digitRatio = calculateDigitRatio(this.leftmostLabel);
        this.hyphenRatio = calculateHyphenRatio(this.leftmostLabel);
        this.uniqueCharacterRatio =
                calculateUniqueCharacterRatio(this.leftmostLabel);
        this.base32Like = isBase32Like(this.leftmostLabel);
        this.base64Like = isBase64Like(this.leftmostLabel);
        this.punycode = containsPunycode(this.domain);
        this.ipLikeLabel = containsIpLikeLabel(this.domain);
        this.suspiciousKeyword = containsSuspiciousKeyword(this.domain);
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getDomain() {
        return domain;
    }

    public int getQueryType() {
        return queryType;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public boolean isQuery() {
        return query;
    }

    public int getOpcode() {
        return opcode;
    }

    public boolean isTruncated() {
        return truncated;
    }

    public boolean isRecursionDesired() {
        return recursionDesired;
    }

    public int getZ() {
        return z;
    }

    public int getRcode() {
        return rcode;
    }

    public int getDomainLength() {
        return domainLength;
    }

    public double getEntropy() {
        return entropy;
    }

    public int getSubdomainCount() {
        return subdomainCount;
    }

    public String getParentDomain() {
        return parentDomain;
    }

    public String getLeftmostLabel() {
        return leftmostLabel;
    }

    public int getLeftmostLabelLength() {
        return leftmostLabelLength;
    }

    public int getMaxLabelLength() {
        return maxLabelLength;
    }

    public double getDigitRatio() {
        return digitRatio;
    }

    public double getHyphenRatio() {
        return hyphenRatio;
    }

    public double getUniqueCharacterRatio() {
        return uniqueCharacterRatio;
    }

    public boolean isBase32Like() {
        return base32Like;
    }

    public boolean isBase64Like() {
        return base64Like;
    }

    public boolean hasPunycode() {
        return punycode;
    }

    public boolean hasIpLikeLabel() {
        return ipLikeLabel;
    }

    public boolean hasSuspiciousKeyword() {
        return suspiciousKeyword;
    }

    private static String normalizeNullable(String value) {
        if (value == null) {
            return null;
        }

        String result = value.trim();
        return result.isEmpty() ? null : result;
    }

    private static String normalizeDomain(String value) {
        if (value == null) {
            return null;
        }

        String result = value.trim().toLowerCase(Locale.ROOT);

        while (result.endsWith(".")) {
            result = result.substring(0, result.length() - 1);
        }

        return result.isEmpty() ? null : result;
    }

    private static double calculateEntropy(String value) {
        if (value == null || value.isEmpty()) {
            return 0.0;
        }

        int[] frequency = new int[Character.MAX_VALUE + 1];
        int length = 0;

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);

            if (c == '.') {
                continue;
            }

            frequency[c]++;
            length++;
        }

        if (length == 0) {
            return 0.0;
        }

        double result = 0.0;

        for (int count : frequency) {
            if (count == 0) {
                continue;
            }

            double probability = (double) count / length;
            result -= probability * Math.log(probability) / LOG_2;
        }

        return result;
    }

    private static int countDots(String value) {
        if (value == null || value.isEmpty()) {
            return 0;
        }

        int count = 0;

        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') {
                count++;
            }
        }

        return count;
    }

    private static String calculateParentDomain(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }

        int index = value.indexOf('.');
        if (index < 0 || index == value.length() - 1) {
            return value;
        }

        return value.substring(index + 1);
    }

    private static String calculateLeftmostLabel(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }

        int index = value.indexOf('.');
        return index < 0 ? value : value.substring(0, index);
    }

    private static int calculateMaxLabelLength(String value) {
        if (value == null || value.isEmpty()) {
            return 0;
        }

        int max = 0;
        int current = 0;

        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') {
                if (current > max) {
                    max = current;
                }
                current = 0;
            } else {
                current++;
            }
        }

        return Math.max(max, current);
    }

    private static double calculateDigitRatio(String value) {
        if (value == null || value.isEmpty()) {
            return 0.0;
        }

        int count = 0;

        for (int i = 0; i < value.length(); i++) {
            if (Character.isDigit(value.charAt(i))) {
                count++;
            }
        }

        return (double) count / value.length();
    }

    private static double calculateHyphenRatio(String value) {
        if (value == null || value.isEmpty()) {
            return 0.0;
        }

        int count = 0;

        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '-') {
                count++;
            }
        }

        return (double) count / value.length();
    }

    private static double calculateUniqueCharacterRatio(String value) {
        if (value == null || value.isEmpty()) {
            return 0.0;
        }

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

    private static boolean isBase32Like(String value) {
        if (value == null || value.length() < 12) {
            return false;
        }

        int valid = 0;

        for (int i = 0; i < value.length(); i++) {
            char c = Character.toUpperCase(value.charAt(i));

            if ((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
                valid++;
            }
        }

        return (double) valid / value.length() >= 0.95;
    }

    private static boolean isBase64Like(String value) {
        if (value == null || value.length() < 16) {
            return false;
        }

        int valid = 0;

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);

            if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '+'
                    || c == '/'
                    || c == '=') {
                valid++;
            }
        }

        return (double) valid / value.length() >= 0.95;
    }

    private static boolean containsPunycode(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String[] labels = value.split("\\.");

        for (String label : labels) {
            if (label.startsWith("xn--")) {
                return true;
            }
        }

        return false;
    }

    private static boolean containsIpLikeLabel(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String[] labels = value.split("\\.");

        for (String label : labels) {
            int digits = 0;
            int hyphens = 0;

            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);

                if (Character.isDigit(c)) {
                    digits++;
                } else if (c == '-') {
                    hyphens++;
                }
            }

            if (digits >= 4 && hyphens >= 1) {
                return true;
            }
        }

        return false;
    }

    private static boolean containsSuspiciousKeyword(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String lower = value.toLowerCase(Locale.ROOT);

        return lower.contains("malware")
                || lower.contains("phishing")
                || lower.contains("exploit")
                || lower.contains("ransom")
                || lower.contains("botnet")
                || lower.contains("keylogger")
                || lower.contains("stealer");
    }

    @Override
    public String toString() {
        return String.format(
                Locale.ROOT,
                "DnsQueryRecord{clientIp='%s', domain='%s', queryType=%d, timestamp=%d}",
                clientIp,
                domain,
                queryType,
                timestamp
        );
    }
}