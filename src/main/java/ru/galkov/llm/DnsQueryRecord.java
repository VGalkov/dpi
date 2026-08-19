package ru.galkov.llm;

import java.util.Locale;

/**
 * ✅ Оптимизация п.6: immutable record для DNS-запроса
 * ✅ Оптимизация п.7: добавлены вычисляемые поля для LLM
 */
public final class DnsQueryRecord {
    private final String clientIp;
    private final String domain;
    private final int queryType;
    private final long timestamp;
    private final boolean isQuery;
    private final int opcode;
    private final boolean isTruncated;
    private final boolean recursionDesired;
    private final int z;
    private final int rcode;

    // ✅ Вычисляемые поля для LLM
    private final int domainLength;
    private final double entropy;
    private final int subdomainCount;

    public DnsQueryRecord(String clientIp, String domain, int queryType, long timestamp,
                          boolean isQuery, int opcode, boolean isTruncated,
                          boolean recursionDesired, int z, int rcode) {
        this.clientIp = clientIp;
        this.domain = domain;
        this.queryType = queryType;
        this.timestamp = timestamp;
        this.isQuery = isQuery;
        this.opcode = opcode;
        this.isTruncated = isTruncated;
        this.recursionDesired = recursionDesired;
        this.z = z;
        this.rcode = rcode;

        // ✅ Предварительный расчёт полей для LLM
        this.domainLength = domain != null ? domain.length() : 0;
        this.entropy = calculateEntropy(domain);
        this.subdomainCount = countSubdomains(domain);
    }

    /**
     * ✅ Расчёт энтропии домена (мера случайности)
     */
    private double calculateEntropy(String domain) {
        if (domain == null || domain.isEmpty()) return 0.0;

        int[] freq = new int[256];
        for (char c : domain.toCharArray()) {
            freq[c]++;
        }

        double entropy = 0.0;
        int len = domain.length();
        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / len;
                entropy -= p * Math.log(p) / Math.log(2);
            }
        }
        return entropy;
    }

    /**
     * ✅ Подсчёт количества поддоменов
     */
    private int countSubdomains(String domain) {
        if (domain == null || domain.isEmpty()) return 0;
        // Считаем точки как разделители поддоменов
        int count = 0;
        for (char c : domain.toCharArray()) {
            if (c == '.') count++;
        }
        return count;
    }

    // ✅ Геттеры
    public String getClientIp() { return clientIp; }
    public String getDomain() { return domain; }
    public int getQueryType() { return queryType; }
    public long getTimestamp() { return timestamp; }
    public boolean isQuery() { return isQuery; }
    public int getOpcode() { return opcode; }
    public boolean isTruncated() { return isTruncated; }
    public boolean isRecursionDesired() { return recursionDesired; }
    public int getZ() { return z; }
    public int getRcode() { return rcode; }
    public int getDomainLength() { return domainLength; }
    public double getEntropy() { return entropy; }
    public int getSubdomainCount() { return subdomainCount; }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "DnsQueryRecord{clientIp='%s', domain='%s', queryType=%d, timestamp=%d}",
                clientIp, domain, queryType, timestamp);
    }
}