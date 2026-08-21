package ru.galkov.llm;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public final class DnsQueryRecord extends AbstractQueryRecord {
    private final String domain;
    private final int queryType;
    private final boolean query;
    private final int opcode;
    private final boolean truncated;
    private final boolean recursionDesired;
    private final int z;
    private final int rcode;
    private final int domainLength;
    private volatile Double entropy;
    private volatile Integer subdomainCount;
    private volatile String parentDomain;
    private volatile String leftmostLabel;
    private volatile Integer leftmostLabelLength;
    private volatile Integer maxLabelLength;
    private volatile Double digitRatio;
    private volatile Double hyphenRatio;
    private volatile Double uniqueCharacterRatio;
    private volatile Boolean base32Like;
    private volatile Boolean base64Like;
    private volatile Boolean punycode;
    private volatile Boolean ipLikeLabel;
    private volatile Boolean suspiciousKeyword;

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
        super(clientIp, timestamp);

        this.domain = normalizeDomain(domain);
        this.queryType = queryType;
        this.query = query;
        this.opcode = opcode;
        this.truncated = truncated;
        this.recursionDesired = recursionDesired;
        this.z = z;
        this.rcode = rcode;
        this.domainLength = this.domain == null ? 0 : this.domain.length();
    }

    @Override
    public String getTarget() { return domain; }

    @Override
    public int getTargetLength() { return domainLength; }

    @Override
    public boolean isTargetIp() { return hasIpLikeLabel(); }

    @Override
    public boolean hasSuspiciousTld() { return false; }

    @Override
    public boolean hasInjectionMarkers() { return hasSuspiciousKeyword(); }

    @Override
    public boolean hasSuspiciousIndicator() { return hasSuspiciousKeyword(); }

    // ✅ Специфичные для DNS методы
    public String getDomain() { return domain; }
    public int getQueryType() { return queryType; }
    public boolean isQuery() { return query; }
    public int getOpcode() { return opcode; }
    public boolean isTruncated() { return truncated; }
    public boolean isRecursionDesired() { return recursionDesired; }
    public int getZ() { return z; }
    public int getRcode() { return rcode; }
    public int getDomainLength() { return domainLength; }

    // ✅ Ленивые getter'ы
    public double getEntropy() {
        Double e = entropy;
        if (e == null) {
            synchronized (this) {
                if (entropy == null) {
                    entropy = calculateEntropy(domain);
                }
                e = entropy;
            }
        }
        return e;
    }

    public int getSubdomainCount() {
        Integer c = subdomainCount;
        if (c == null) {
            synchronized (this) {
                if (subdomainCount == null) {
                    subdomainCount = countDots(domain);
                }
                c = subdomainCount;
            }
        }
        return c;
    }

    public String getParentDomain() {
        String p = parentDomain;
        if (p == null) {
            synchronized (this) {
                if (parentDomain == null) {
                    parentDomain = calculateParentDomain(domain);
                }
                p = parentDomain;
            }
        }
        return p;
    }

    public String getLeftmostLabel() {
        String l = leftmostLabel;
        if (l == null) {
            synchronized (this) {
                if (leftmostLabel == null) {
                    leftmostLabel = calculateLeftmostLabel(domain);
                }
                l = leftmostLabel;
            }
        }
        return l;
    }

    public int getLeftmostLabelLength() {
        Integer l = leftmostLabelLength;
        if (l == null) {
            synchronized (this) {
                if (leftmostLabelLength == null) {
                    leftmostLabelLength = getLeftmostLabel().length();
                }
                l = leftmostLabelLength;
            }
        }
        return l;
    }

    public int getMaxLabelLength() {
        Integer m = maxLabelLength;
        if (m == null) {
            synchronized (this) {
                if (maxLabelLength == null) {
                    maxLabelLength = calculateMaxLabelLength(domain);
                }
                m = maxLabelLength;
            }
        }
        return m;
    }

    public double getDigitRatio() {
        Double d = digitRatio;
        if (d == null) {
            synchronized (this) {
                if (digitRatio == null) {
                    digitRatio = calculateDigitRatio(getLeftmostLabel());
                }
                d = digitRatio;
            }
        }
        return d;
    }

    public double getHyphenRatio() {
        Double h = hyphenRatio;
        if (h == null) {
            synchronized (this) {
                if (hyphenRatio == null) {
                    hyphenRatio = calculateHyphenRatio(getLeftmostLabel());
                }
                h = hyphenRatio;
            }
        }
        return h;
    }

    public double getUniqueCharacterRatio() {
        Double u = uniqueCharacterRatio;
        if (u == null) {
            synchronized (this) {
                if (uniqueCharacterRatio == null) {
                    uniqueCharacterRatio = calculateUniqueCharacterRatio(getLeftmostLabel());
                }
                u = uniqueCharacterRatio;
            }
        }
        return u;
    }

    public boolean isBase32Like() {
        Boolean b = base32Like;
        if (b == null) {
            synchronized (this) {
                if (base32Like == null) {
                    base32Like = isBase32Like(getLeftmostLabel());
                }
                b = base32Like;
            }
        }
        return b;
    }

    public boolean isBase64Like() {
        Boolean b = base64Like;
        if (b == null) {
            synchronized (this) {
                if (base64Like == null) {
                    base64Like = isBase64Like(getLeftmostLabel());
                }
                b = base64Like;
            }
        }
        return b;
    }

    public boolean hasPunycode() {
        Boolean p = punycode;
        if (p == null) {
            synchronized (this) {
                if (punycode == null) {
                    punycode = containsPunycode(domain);
                }
                p = punycode;
            }
        }
        return p;
    }

    public boolean hasIpLikeLabel() {
        Boolean i = ipLikeLabel;
        if (i == null) {
            synchronized (this) {
                if (ipLikeLabel == null) {
                    ipLikeLabel = containsIpLikeLabel(domain);
                }
                i = ipLikeLabel;
            }
        }
        return i;
    }

    public boolean hasSuspiciousKeyword() {
        Boolean s = suspiciousKeyword;
        if (s == null) {
            synchronized (this) {
                if (suspiciousKeyword == null) {
                    suspiciousKeyword = containsSuspiciousKeyword(domain);
                }
                s = suspiciousKeyword;
            }
        }
        return s;
    }

    @Override
    public String toString() {
        return "DnsQueryRecord{" + buildBaseToString() +
                ", domain='" + domain + "', queryType=" + queryType + '}';
    }
}