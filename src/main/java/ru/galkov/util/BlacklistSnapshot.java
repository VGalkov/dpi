package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class BlacklistSnapshot {
    private static final Logger logger = LoggerFactory.getLogger(BlacklistSnapshot.class);

    private final DomainTrie domainTrie;
    private final Set<String> ipSet;
    private final Set<IpCidr> cidrSet;
    private final long timestamp;

    private static final int DEFAULT_MAX_IP_CACHE_SIZE = 2000;
    private final int maxIpCacheSize;
    private final Map<String, BlockDecision> ipCache;
    private final Map<String, BlockDecision> domainCache;
    private final Object ipCacheLock = new Object();

    public BlacklistSnapshot(
            DomainTrie domainTrie,
            Set<String> ipSet,
            Set<IpCidr> cidrSet
    ) {
        this.domainTrie = domainTrie;
        this.ipSet = ipSet;
        this.cidrSet = cidrSet;
        this.timestamp = System.currentTimeMillis();

        this.maxIpCacheSize = getMaxIpCacheSize();

        this.ipCache = Collections.synchronizedMap(
                new LinkedHashMap<String, BlockDecision>(16, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(
                            Map.Entry<String, BlockDecision> eldest
                    ) {
                        if (size() > maxIpCacheSize) {
                            logger.debug(
                                    "BlacklistSnapshot.ipCache: evicted oldest entry (size={} > max={})",
                                    size(),
                                    maxIpCacheSize
                            );
                            return true;
                        }
                        return false;
                    }
                }
        );

        this.domainCache = new ConcurrentHashMap<>(1024);
    }

    public BlacklistSnapshot(DomainTrie domainTrie, Set<String> ipSet) {
        this(domainTrie, ipSet, Collections.emptySet());
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
        } catch (IllegalStateException e) {
            logger.debug(
                    "BlacklistSnapshot: AppConfig not initialized, using default max-ip-cache-size={}",
                    DEFAULT_MAX_IP_CACHE_SIZE
            );
            return DEFAULT_MAX_IP_CACHE_SIZE;
        } catch (Exception e) {
            logger.debug(
                    "BlacklistSnapshot: using default max-ip-cache-size={}",
                    DEFAULT_MAX_IP_CACHE_SIZE
            );
            return DEFAULT_MAX_IP_CACHE_SIZE;
        }
    }

    public BlockDecision checkIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return BlockDecision.allow();
        }

        synchronized (ipCacheLock) {
            BlockDecision cached = ipCache.get(ip);
            if (cached != null) {
                return cached;
            }

            boolean blocked = ipSet.contains(ip);

            if (!blocked && !cidrSet.isEmpty()) {
                try {
                    for (IpCidr cidr : cidrSet) {
                        if (cidr.contains(ip)) {
                            blocked = true;
                            break;
                        }
                    }
                } catch (Exception e) {
                    logger.debug(
                            "BlacklistSnapshot.checkIp: CIDR check failed for ip={}: {}",
                            ip,
                            e.getMessage()
                    );
                }
            }

            BlockDecision decision = blocked
                    ? BlockDecision.blockIpExact("ip:" + ip, "blacklist")
                    : BlockDecision.allow();

            ipCache.put(ip, decision);
            return decision;
        }
    }

    public BlockDecision checkDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return BlockDecision.allow();
        }

        BlockDecision cached = domainCache.get(domain);
        if (cached != null) {
            return cached;
        }

        String normalized = HostNormalizer.normalizeHost(domain);
        if (normalized == null) {
            return BlockDecision.allow();
        }

        boolean blocked = domainTrie.matches(normalized);
        BlockDecision decision = blocked
                ? BlockDecision.blockDomain(
                DomainTrie.MatchType.SUBTREE,
                normalized,
                "blacklist"
        )
                : BlockDecision.allow();

        domainCache.put(domain, decision);
        return decision;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public int getDomainRuleCount() {
        return 0;
    }

    public int getIpRuleCount() {
        return ipSet.size() + cidrSet.size();
    }

    public int getIpCacheSize() {
        return ipCache.size();
    }
}