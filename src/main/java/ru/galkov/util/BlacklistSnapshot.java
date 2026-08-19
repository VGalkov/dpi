package ru.galkov.util;

import java.util.Collections;
import java.util.Set;

public final class BlacklistSnapshot {
    private final DomainTrie domainTrie;
    private final Set<String> ips;
    private final Set<IpCidr> ipCidrs;

    public BlacklistSnapshot(DomainTrie domainTrie, Set<String> ips, Set<IpCidr> ipCidrs) {
        this.domainTrie = domainTrie != null ? domainTrie : new DomainTrie();
        this.ips = ips != null ? ips : Collections.emptySet();
        this.ipCidrs = ipCidrs != null ? ipCidrs : Collections.emptySet();
    }

    public BlockDecision checkIp(String ip) {
        if (ip == null || ip.isEmpty()) return BlockDecision.allow();
        if (ips.contains(ip)) {
            return BlockDecision.blockIpExact(ip, "blacklist");
        }
        for (IpCidr cidr : ipCidrs) {
            if (cidr != null && cidr.contains(ip)) {
                return BlockDecision.blockIpCidr(ip, "blacklist");
            }
        }
        return BlockDecision.allow();
    }

    public BlockDecision checkDomain(String domain) {
        // DomainTrie.matches это O(m) где m - глубина trie
        return domainTrie.matches(domain)
                ? BlockDecision.blockDomain(DomainTrie.MatchType.EXACT, domain, "blacklist")
                : BlockDecision.allow();
    }

    public static BlacklistSnapshot empty() {
        return new BlacklistSnapshot(new DomainTrie(), Collections.emptySet(), Collections.emptySet());
    }
}