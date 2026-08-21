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

    // ✅ Ленивые getter'ы с double-checked locking
    public double getEntropy() {
        Double e = entropy;
        if (e == null) {
            synchronized (this) {
                e = entropy;
                if (e == null) {
                    entropy = e = calculateEntropy(domain);
                }
            }
        }
        return e;
    }

    public int getSubdomainCount() {
        Integer c = subdomainCount;
        if (c == null) {
            synchronized (this) {
                c = subdomainCount;
                if (c == null) {
                    subdomainCount = c = countDots(domain);
                }
            }
        }
        return c;
    }

    public String getParentDomain() {
        String p = parentDomain;
        if (p == null) {
            synchronized (this) {
                p = parentDomain;
                if (p == null) {
                    parentDomain = p = calculateParentDomain(domain);
                }
            }
        }
        return p;
    }

    public String getLeftmostLabel() {
        String l = leftmostLabel;
        if (l == null) {
            synchronized (this) {
                l = leftmostLabel;
                if (l == null) {
                    leftmostLabel = l = calculateLeftmostLabel(domain);
                }
            }
        }
        return l;
    }

    public int getLeftmostLabelLength() {
        Integer l = leftmostLabelLength;
        if (l == null) {
            synchronized (this) {
                l = leftmostLabelLength;
                if (l == null) {
                    leftmostLabelLength = l = getLeftmostLabel().length();
                }
            }
        }
        return l;
    }

    public int getMaxLabelLength() {
        Integer m = maxLabelLength;
        if (m == null) {
            synchronized (this) {
                m = maxLabelLength;
                if (m == null) {
                    maxLabelLength = m = calculateMaxLabelLength(domain);
                }
            }
        }
        return m;
    }

    public double getDigitRatio() {
        Double d = digitRatio;
        if (d == null) {
            synchronized (this) {
                d = digitRatio;
                if (d == null) {
                    digitRatio = d = calculateDigitRatio(getLeftmostLabel());
                }
            }
        }
        return d;
    }

    public double getHyphenRatio() {
        Double h = hyphenRatio;
        if (h == null) {
            synchronized (this) {
                h = hyphenRatio;
                if (h == null) {
                    hyphenRatio = h = calculateHyphenRatio(getLeftmostLabel());
                }
            }
        }
        return h;
    }

    public double getUniqueCharacterRatio() {
        Double u = uniqueCharacterRatio;
        if (u == null) {
            synchronized (this) {
                u = uniqueCharacterRatio;
                if (u == null) {
                    uniqueCharacterRatio = u = calculateUniqueCharacterRatio(getLeftmostLabel());
                }
            }
        }
        return u;
    }

    public boolean isBase32Like() {
        Boolean b = base32Like;
        if (b == null) {
            synchronized (this) {
                b = base32Like;
                if (b == null) {
                    base32Like = b = isBase32Like(getLeftmostLabel());
                }
            }
        }
        return b;
    }

    public boolean isBase64Like() {
        Boolean b = base64Like;
        if (b == null) {
            synchronized (this) {
                b = base64Like;
                if (b == null) {
                    base64Like = b = isBase64Like(getLeftmostLabel());
                }
            }
        }
        return b;
    }

    public boolean hasPunycode() {
        Boolean p = punycode;
        if (p == null) {
            synchronized (this) {
                p = punycode;
                if (p == null) {
                    punycode = p = containsPunycode(domain);
                }
            }
        }
        return p;
    }

    public boolean hasIpLikeLabel() {
        Boolean i = ipLikeLabel;
        if (i == null) {
            synchronized (this) {
                i = ipLikeLabel;
                if (i == null) {
                    ipLikeLabel = i = containsIpLikeLabel(domain);
                }
            }
        }
        return i;
    }

    public boolean hasSuspiciousKeyword() {
        Boolean s = suspiciousKeyword;
        if (s == null) {
            synchronized (this) {
                s = suspiciousKeyword;
                if (s == null) {
                    suspiciousKeyword = s = containsSuspiciousKeyword(domain);
                }
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