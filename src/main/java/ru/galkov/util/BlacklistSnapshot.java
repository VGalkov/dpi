package ru.galkov.util;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class BlacklistSnapshot {
    private final DomainTrie domainTrie;
    private final Set<String> ips;
    private final Set<IpCidr> ipCidrs;

    // ✅ П.25: Кэш для checkIp()
    private final Map<String, BlockDecision> ipCache = new ConcurrentHashMap<>(1024);
    private static final int MAX_IP_CACHE_SIZE = 2000;

    public BlacklistSnapshot(DomainTrie domainTrie, Set<String> ips, Set<IpCidr> ipCidrs) {
        this.domainTrie = domainTrie != null ? domainTrie : new DomainTrie();
        this.ips = ips != null ? ips : Collections.emptySet();
        this.ipCidrs = ipCidrs != null ? ipCidrs : Collections.emptySet();
    }

    /**
     * ✅ П.25: Кэш для checkIp()
     */
    public BlockDecision checkIp(String ip) {
        if (ip == null || ip.isEmpty()) return BlockDecision.allow();

        // Проверка кэша
        BlockDecision cached = ipCache.get(ip);
        if (cached != null) return cached;

        // Оригинальная логика
        BlockDecision result;
        if (ips.contains(ip)) {
            result = BlockDecision.blockIpExact(ip, "blacklist");
        } else {
            result = BlockDecision.allow();
            for (IpCidr cidr : ipCidrs) {
                if (cidr != null && cidr.contains(ip)) {
                    result = BlockDecision.blockIpCidr(ip, "blacklist");
                    break;
                }
            }
        }

        // Запись в кэш с ограничением размера
        if (ipCache.size() >= MAX_IP_CACHE_SIZE) {
            ipCache.clear();
        }
        ipCache.put(ip, result);

        return result;
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