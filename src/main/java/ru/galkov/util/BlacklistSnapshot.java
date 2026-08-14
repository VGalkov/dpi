package ru.galkov.util;

import java.util.Collections;
import java.util.Set;

public final class BlacklistSnapshot {

    private final DomainTrie domainTrie;
    private final Set<String> ips;
    private final Set<IpCidr> ipCidrs;

    public BlacklistSnapshot(DomainTrie domainTrie, Set<String> ips, Set<IpCidr> ipCidrs) {
        this.domainTrie = domainTrie;
        this.ips = ips;
        this.ipCidrs = ipCidrs != null ? ipCidrs : Collections.emptySet();
    }

    public BlockDecision checkIp(String ip) {
        String normalizedIp = HostNormalizer.normalizeIp(ip);

        if (normalizedIp == null)
            return BlockDecision.allow();

        if (ips.contains(normalizedIp))
            return BlockDecision.blockIpExact(normalizedIp, "blacklist");

        for (IpCidr cidr : ipCidrs) {
            if (cidr.contains(normalizedIp))
                return BlockDecision.blockIpCidr(normalizedIp, "blacklist");
        }

        return BlockDecision.allow();
    }

    public BlockDecision checkDomain(String domain) {
        String normalizedDomain = HostNormalizer.normalizeHost(domain);

        if (normalizedDomain == null)
            return BlockDecision.allow();

        if (domainTrie.matches(normalizedDomain)) {
            return BlockDecision.blockDomain(DomainTrie.MatchType.EXACT, normalizedDomain, "blacklist");
        }

        return BlockDecision.allow();
    }

    public static BlacklistSnapshot empty() {
        return new BlacklistSnapshot(new DomainTrie(), Collections.emptySet(), Collections.emptySet());
    }
}