package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class BlacklistSnapshot {
    private static final Logger logger = LoggerFactory.getLogger(BlacklistSnapshot.class);

    private final DomainTrie domainTrie;
    private final long timestamp;

    private final Map<String, Boolean> ipExactMap;
    private final Map<String, IpCidr> cidrPrefixMap;
    private final Set<IpCidr> cidrSet;

    private static final int DEFAULT_MAX_IP_CACHE_SIZE = 10000;
    private static final int DEFAULT_MAX_DOMAIN_CACHE_SIZE = 20000;
    private static final long DEFAULT_CACHE_TTL_MILLIS = 60_000L;

    private final int maxIpCacheSize;
    private final int maxDomainCacheSize;
    private final long cacheTtlMillis;

    private final Map<String, CacheEntry<BlockDecision>> ipCache;
    private final Map<String, CacheEntry<BlockDecision>> domainCache;

    public BlacklistSnapshot(DomainTrie domainTrie, Set<String> ipSet, Set<IpCidr> cidrSet) {
        this.domainTrie = domainTrie;
        this.timestamp = System.currentTimeMillis();

        this.maxIpCacheSize = getMaxIpCacheSize();
        this.maxDomainCacheSize = getMaxDomainCacheSize();
        this.cacheTtlMillis = getCacheTtlMillis();

        this.ipExactMap = new ConcurrentHashMap<>(ipSet.size());
        for (String ip : ipSet) {
            ipExactMap.put(ip, true);
        }

        // ✅ заполняем изменяемый набор, затем оборачиваем (фикс UnsupportedOperationException)
        this.cidrPrefixMap = new ConcurrentHashMap<>(cidrSet.size());
        Set<IpCidr> mutableCidrSet = ConcurrentHashMap.newKeySet();
        for (IpCidr cidr : cidrSet) {
            mutableCidrSet.add(cidr);
            String prefix = getCidrPrefix(cidr);
            cidrPrefixMap.put(prefix, cidr);
        }
        this.cidrSet = Collections.unmodifiableSet(mutableCidrSet);

        this.ipCache = Collections.synchronizedMap(
                new LinkedHashMap<String, CacheEntry<BlockDecision>>(16, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(
                            Map.Entry<String, CacheEntry<BlockDecision>> eldest
                    ) {
                        return size() > maxIpCacheSize;
                    }
                }
        );

        this.domainCache = Collections.synchronizedMap(
                new LinkedHashMap<String, CacheEntry<BlockDecision>>(16, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(
                            Map.Entry<String, CacheEntry<BlockDecision>> eldest
                    ) {
                        return size() > maxDomainCacheSize;
                    }
                }
        );
    }

    private String getCidrPrefix(IpCidr cidr) {
        String network = cidr.toString();
        int slashIndex = network.indexOf('/');
        if (slashIndex > 0) {
            return network.substring(0, slashIndex);
        }
        return network;
    }

    public static BlacklistSnapshot empty() {
        return new BlacklistSnapshot(
                new DomainTrie(),
                Collections.emptySet(),
                Collections.emptySet()
        );
    }

    private static int getMaxIpCacheSize() {
        try {
            ru.galkov.AppConfig config = ru.galkov.Main.getConfig();
            if (config == null) {
                return DEFAULT_MAX_IP_CACHE_SIZE;
            }
            return config.getInt("blacklist.snapshot.max-ip-cache-size");
        } catch (Exception e) {
            logger.debug("BlacklistSnapshot: using default max-ip-cache-size={}", DEFAULT_MAX_IP_CACHE_SIZE);
            return DEFAULT_MAX_IP_CACHE_SIZE;
        }
    }

    private static int getMaxDomainCacheSize() {
        try {
            ru.galkov.AppConfig config = ru.galkov.Main.getConfig();
            return config.getInt("blacklist.snapshot.max-domain-cache-size");
        } catch (Exception e) {
            logger.debug(
                    "BlacklistSnapshot: using default max-domain-cache-size={}",
                    DEFAULT_MAX_DOMAIN_CACHE_SIZE
            );
            return DEFAULT_MAX_DOMAIN_CACHE_SIZE;
        }
    }

    private static long getCacheTtlMillis() {
        try {
            ru.galkov.AppConfig config = ru.galkov.Main.getConfig();
            int value = config.getInt("blacklist.snapshot.cache-ttl-millis");
            return value > 0 ? value : DEFAULT_CACHE_TTL_MILLIS;
        } catch (Exception e) {
            return DEFAULT_CACHE_TTL_MILLIS;
        }
    }

    public BlockDecision checkIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return BlockDecision.allow();
        }

        String normalizedIp = HostNormalizer.normalizeHost(ip);
        if (normalizedIp == null) {
            return BlockDecision.allow();
        }

        CacheEntry<BlockDecision> cached = ipCache.get(normalizedIp);
        if (cached != null && !cached.isExpired(cacheTtlMillis)) {
            return cached.value;
        }

        Boolean exactMatch = ipExactMap.get(normalizedIp);
        if (exactMatch != null && exactMatch) {
            BlockDecision decision = BlockDecision.blockIpExact("ip:" + normalizedIp, "blacklist");
            ipCache.put(normalizedIp, new CacheEntry<>(decision));
            return decision;
        }

        boolean blocked = !cidrPrefixMap.isEmpty()
                && matchesCidr(normalizedIp);

        BlockDecision decision = blocked
                ? BlockDecision.blockIpExact("ip:" + normalizedIp, "blacklist")
                : BlockDecision.allow();

        ipCache.put(normalizedIp, new CacheEntry<>(decision));
        return decision;
    }

    // ✅ ГЛАВНЫЙ ФИКС: BloomFilter-гейт удалён. Всегда выполняем поиск в trie.
    //    Раньше false->allow ложно пропускал поддомены SUBTREE-правил.
    public BlockDecision checkDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return BlockDecision.allow();
        }

        String normalized = HostNormalizer.normalizeHost(domain);
        if (normalized == null) {
            return BlockDecision.allow();
        }

        CacheEntry<BlockDecision> cached = domainCache.get(normalized);
        if (cached != null && !cached.isExpired(cacheTtlMillis)) {
            return cached.value;
        }

        boolean blocked = domainTrie.matches(normalized);
        BlockDecision decision = blocked
                ? BlockDecision.blockDomain(
                DomainTrie.MatchType.SUBTREE,
                normalized,
                "blacklist"
        )
                : BlockDecision.allow();

        domainCache.put(normalized, new CacheEntry<>(decision));
        return decision;
    }

    private boolean matchesCidr(String ip) {
        String ipPrefix = getIpPrefix(ip);
        IpCidr direct = cidrPrefixMap.get(ipPrefix);
        if (direct != null && direct.contains(ip)) {
            return true;
        }

        for (IpCidr cidr : cidrSet) {
            if (cidr.contains(ip)) {
                return true;
            }
        }

        return false;
    }

    private String getIpPrefix(String ip) {
        int lastDot = ip.lastIndexOf('.');
        if (lastDot > 0) {
            return ip.substring(0, lastDot);
        }
        return ip;
    }

    private static final class CacheEntry<V> {
        private final V value;
        private final long created;

        CacheEntry(V value) {
            this.value = value;
            this.created = System.currentTimeMillis();
        }

        boolean isExpired(long ttlMillis) {
            return ttlMillis > 0
                    && (System.currentTimeMillis() - created) > ttlMillis;
        }
    }
}