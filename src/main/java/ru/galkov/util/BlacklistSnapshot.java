package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 *
 * ✅ П.13: LRU eviction policy для ipCache
 */
public class BlacklistSnapshot {
    private static final Logger logger = LoggerFactory.getLogger(BlacklistSnapshot.class);

    private final DomainTrie domainTrie;
    private final Set<String> ipSet;
    private final Set<IpCidr> cidrSet;
    private final long timestamp;

    // ✅ П.13: LRU кэш для IP с eviction policy (перенесено из static в instance)
    private static final int DEFAULT_MAX_IP_CACHE_SIZE = 2000;
    private final int maxIpCacheSize;
    private final Map<String, BlockDecision> ipCache;

    /**
     * ✅ П.13: Конструктор с CIDR
     */
    public BlacklistSnapshot(DomainTrie domainTrie, Set<String> ipSet, Set<IpCidr> cidrSet) {
        this.domainTrie = domainTrie;
        this.ipSet = ipSet;
        this.cidrSet = cidrSet;
        this.timestamp = System.currentTimeMillis();

        // ✅ П.13: Получение значения в конструкторе (не в static)
        this.maxIpCacheSize = getMaxIpCacheSize();

        // ✅ П.13: LinkedHashMap с accessOrder=true для LRU eviction
        this.ipCache = new LinkedHashMap<String, BlockDecision>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, BlockDecision> eldest) {
                if (size() > maxIpCacheSize) {
                    logger.debug("BlacklistSnapshot.ipCache: evicted oldest entry (size={} > max={})",
                            size(), maxIpCacheSize);
                    return true;
                }
                return false;
            }
        };
    }

    /**
     * ✅ П.13: Конструктор без CIDR (для обратной совместимости)
     */
    public BlacklistSnapshot(DomainTrie domainTrie, Set<String> ipSet) {
        this(domainTrie, ipSet, Collections.emptySet());
    }

    /**
     * ✅ П.13: Пустой snapshot для fallback
     */
    public static BlacklistSnapshot empty() {
        return new BlacklistSnapshot(new DomainTrie(), Collections.emptySet(), Collections.emptySet());
    }

    /**
     * ✅ П.13: Получение значения max-ip-cache-size с fallback
     */
    private static int getMaxIpCacheSize() {
        try {
            return ru.galkov.Main.getConfig().getInt("blacklist.snapshot.max-ip-cache-size");
        } catch (Exception e) {
            logger.debug("BlacklistSnapshot: using default max-ip-cache-size={}", DEFAULT_MAX_IP_CACHE_SIZE);
            return DEFAULT_MAX_IP_CACHE_SIZE;
        }
    }

    public BlockDecision checkIp(String ip) {
        if (ip == null || ip.isEmpty()) return BlockDecision.allow();
        BlockDecision cached = ipCache.get(ip);
        if (cached != null) return cached;

        // Проверка точного совпадения IP
        boolean blocked = ipSet.contains(ip);

        // ✅ П.13: Проверка CIDR если точное совпадение не найдено
        if (!blocked && !cidrSet.isEmpty()) {
            try {
                for (IpCidr cidr : cidrSet) {
                    if (cidr.contains(ip)) {
                        blocked = true;
                        break;
                    }
                }
            } catch (Exception e) {
                logger.debug("BlacklistSnapshot.checkIp: CIDR check failed for ip={}: {}", ip, e.getMessage());
            }
        }

        BlockDecision decision = blocked
                ? BlockDecision.blockIpExact("ip:" + ip, "blacklist")
                : BlockDecision.allow();

        ipCache.put(ip, decision);
        return decision;
    }

    public BlockDecision checkDomain(String domain) {
        if (domain == null || domain.isEmpty()) return BlockDecision.allow();
        String normalized = HostNormalizer.normalizeHost(domain);
        if (normalized == null) return BlockDecision.allow();

        boolean blocked = domainTrie.matches(normalized);
        if (blocked) {
            return BlockDecision.blockDomain(DomainTrie.MatchType.SUBTREE, normalized, "blacklist");
        }
        return BlockDecision.allow();
    }

    public long getTimestamp() {
        return timestamp;
    }

    public int getDomainRuleCount() {
        // DomainTrie не хранит счётчик правил, возвращаем 0
        return 0;
    }

    public int getIpRuleCount() {
        return ipSet.size() + cidrSet.size();
    }

    public int getIpCacheSize() {
        return ipCache.size();
    }
}