package ru.galkov.llm;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class DnsQueryRecord {
    private final String clientIp;
    private final String domain;
    private final int queryType;
    private final long timestamp;
    private final int domainLength;
    private final double entropy;
    private final int subdomainCount;

    private final boolean isQuery;
    private final int opcode;
    private final boolean isTruncated;
    private final boolean recursionDesired;
    private final int z;
    private final int rcode;

    public DnsQueryRecord(String clientIp, String domain, int queryType, long timestamp,
                          boolean isQuery, int opcode, boolean isTruncated,
                          boolean recursionDesired, int z, int rcode) {
        this.clientIp = clientIp;
        this.domain = domain;
        this.queryType = queryType;
        this.timestamp = timestamp;
        this.domainLength = domain != null ? domain.length() : 0;
        this.entropy = calculateEntropy(domain);
        this.subdomainCount = countSubdomains(domain);
        this.isQuery = isQuery;
        this.opcode = opcode;
        this.isTruncated = isTruncated;
        this.recursionDesired = recursionDesired;
        this.z = z;
        this.rcode = rcode;
    }

    private static double calculateEntropy(String domain) {
        if (domain == null || domain.isEmpty()) return 0.0;

        int[] freq = new int[256];
        for (char c : domain.toCharArray()) {
            freq[c]++;
        }

        double entropy = 0.0;
        double len = domain.length();

        for (int count : freq) {
            if (count > 0) {
                double p = count / len;
                entropy -= p * Math.log(p) / Math.log(2);
            }
        }

        return entropy;
    }

    private static int countSubdomains(String domain) {
        if (domain == null || domain.isEmpty()) return 0;
        int dots = 0;
        for (char c : domain.toCharArray()) {
            if (c == '.') dots++;
        }
        return dots;
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

    public int getDomainLength() {
        return domainLength;
    }

    public double getEntropy() {
        return entropy;
    }

    public int getSubdomainCount() {
        return subdomainCount;
    }

    public boolean isQuery() {
        return isQuery;
    }

    public int getOpcode() {
        return opcode;
    }

    public boolean isTruncated() {
        return isTruncated;
    }

    public boolean isRecursionDesired() {
        return recursionDesired;
    }

    public int getRcode() {
        return rcode;
    }
}