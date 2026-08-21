package ru.galkov.llm;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public final class DnsQueryRecord implements QueryRecord {
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
        this.clientIp = QueryRecordUtils.normalizeNullable(clientIp);
        this.domain = QueryRecordUtils.normalizeDomain(domain);
        this.queryType = queryType;
        this.timestamp = timestamp;
        this.query = query;
        this.opcode = opcode;
        this.truncated = truncated;
        this.recursionDesired = recursionDesired;
        this.z = z;
        this.rcode = rcode;

        this.domainLength = this.domain == null ? 0 : this.domain.length();
        this.entropy = QueryRecordUtils.calculateEntropy(this.domain);
        this.subdomainCount = QueryRecordUtils.countDots(this.domain);
        this.parentDomain = QueryRecordUtils.calculateParentDomain(this.domain);
        this.leftmostLabel = QueryRecordUtils.calculateLeftmostLabel(this.domain);
        this.leftmostLabelLength = this.leftmostLabel.length();
        this.maxLabelLength = QueryRecordUtils.calculateMaxLabelLength(this.domain);
        this.digitRatio = QueryRecordUtils.calculateDigitRatio(this.leftmostLabel);
        this.hyphenRatio = QueryRecordUtils.calculateHyphenRatio(this.leftmostLabel);
        this.uniqueCharacterRatio = QueryRecordUtils.calculateUniqueCharacterRatio(this.leftmostLabel);
        this.base32Like = QueryRecordUtils.isBase32Like(this.leftmostLabel);
        this.base64Like = QueryRecordUtils.isBase64Like(this.leftmostLabel);
        this.punycode = QueryRecordUtils.containsPunycode(this.domain);
        this.ipLikeLabel = QueryRecordUtils.containsIpLikeLabel(this.domain);
        this.suspiciousKeyword = QueryRecordUtils.containsSuspiciousKeyword(this.domain);
    }

    // ✅ Реализация интерфейса QueryRecord
    @Override
    public String getClientIp() { return clientIp; }

    @Override
    public long getTimestamp() { return timestamp; }

    @Override
    public String getTarget() { return domain; }

    @Override
    public int getTargetLength() { return domainLength; }

    @Override
    public boolean isTargetIp() { return ipLikeLabel; }

    @Override
    public boolean hasSuspiciousTld() { return false; } // DNS не имеет TLD в том же смысле

    @Override
    public boolean hasInjectionMarkers() { return suspiciousKeyword; }

    @Override
    public boolean hasSuspiciousIndicator() { return suspiciousKeyword; }

    // ✅ Специфичные для DNS методы
    public String getDomain() { return domain; }
    public int getQueryType() { return queryType; }
    public boolean isQuery() { return query; }
    public int getOpcode() { return opcode; }
    public boolean isTruncated() { return truncated; }
    public boolean isRecursionDesired() { return recursionDesired; }
    public int getZ() { return z; }
    public int getRcode() { return rcode; }
    public double getEntropy() { return entropy; }
    public int getSubdomainCount() { return subdomainCount; }
    public String getParentDomain() { return parentDomain; }
    public String getLeftmostLabel() { return leftmostLabel; }
    public int getLeftmostLabelLength() { return leftmostLabelLength; }
    public int getMaxLabelLength() { return maxLabelLength; }
    public double getDigitRatio() { return digitRatio; }
    public double getHyphenRatio() { return hyphenRatio; }
    public double getUniqueCharacterRatio() { return uniqueCharacterRatio; }
    public boolean isBase32Like() { return base32Like; }
    public boolean isBase64Like() { return base64Like; }
    public boolean hasPunycode() { return punycode; }
    public boolean hasIpLikeLabel() { return ipLikeLabel; }
    public boolean hasSuspiciousKeyword() { return suspiciousKeyword; }

    @Override
    public String toString() {
        return "DnsQueryRecord{clientIp='" + clientIp + "', domain='" + domain +
                "', queryType=" + queryType + ", timestamp=" + timestamp + '}';
    }
}