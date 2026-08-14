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

    public boolean matchesDomain(String domain) {
        return domainTrie.matches(domain);
    }

    public boolean containsIp(String ip) {
        if (ips.contains(ip))
            return true;

        for (IpCidr cidr : ipCidrs) {
            if (cidr.contains(ip))
                return true;
        }

        return false;
    }

    public static BlacklistSnapshot empty() {
        return new BlacklistSnapshot(new DomainTrie(), Collections.emptySet(), Collections.emptySet());
    }
}