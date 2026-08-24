package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.AppConfig;
import ru.galkov.Main;

import java.net.InetAddress;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Immutable blacklist snapshot with bounded local decision caches.
 *
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class BlacklistSnapshot {
    private static final Logger logger =
            LoggerFactory.getLogger(
                    BlacklistSnapshot.class
            );

    private static final int DEFAULT_MAX_IP_CACHE_SIZE =
            100_000;

    private static final int DEFAULT_MAX_DOMAIN_CACHE_SIZE =
            200_000;

    private static final long DEFAULT_CACHE_TTL_MILLIS =
            60_000L;

    private final DomainTrie domainTrie;
    private final Set<String> exactIps;
    private final Set<IpCidr> cidrs;
    private final IpPrefixIndex ipPrefixIndex;
    private final long timestamp;

    private final int maxIpCacheSize;
    private final int maxDomainCacheSize;
    private final long cacheTtlMillis;

    private final Map<String, CacheEntry> ipCache;
    private final Map<String, CacheEntry> domainCache;

    public BlacklistSnapshot(
            DomainTrie domainTrie,
            Set<String> ipSet,
            Set<IpCidr> cidrSet
    ) {
        this.domainTrie =
                domainTrie == null
                        ? new DomainTrie()
                        : domainTrie;

        this.exactIps =
                immutableIpSet(
                        ipSet
                );

        this.cidrs =
                immutableCidrSet(
                        cidrSet
                );

        this.ipPrefixIndex =
                IpPrefixIndex.build(
                        this.cidrs
                );

        this.timestamp =
                System.currentTimeMillis();

        AppConfig config =
                safeConfig();

        this.maxIpCacheSize =
                positiveInt(
                        config,
                        "blacklist.snapshot.max-ip-cache-size",
                        DEFAULT_MAX_IP_CACHE_SIZE
                );

        this.maxDomainCacheSize =
                positiveInt(
                        config,
                        "blacklist.snapshot.max-domain-cache-size",
                        DEFAULT_MAX_DOMAIN_CACHE_SIZE
                );

        this.cacheTtlMillis =
                positiveLong(
                        config,
                        "blacklist.snapshot.cache-ttl-millis",
                        DEFAULT_CACHE_TTL_MILLIS
                );

        this.ipCache =
                createLruCache(
                        maxIpCacheSize
                );

        this.domainCache =
                createLruCache(
                        maxDomainCacheSize
                );
    }

    public static BlacklistSnapshot empty() {
        return new BlacklistSnapshot(
                null,
                Collections.emptySet(),
                Collections.emptySet()
        );
    }

    public BlockDecision checkIp(
            String ip
    ) {
        String normalized =
                HostNormalizer.normalizeIp(
                        ip
                );

        if (normalized == null) {
            return BlockDecision.allow();
        }

        CacheEntry cached =
                ipCache.get(
                        normalized
                );

        if (cached != null) {
            if (
                    !cached.expired(
                            cacheTtlMillis
                    )
            ) {
                return cached.decision;
            }

            ipCache.remove(
                    normalized,
                    cached
            );
        }

        BlockDecision decision;

        if (
                exactIps.contains(
                        normalized
                )
        ) {
            decision =
                    BlockDecision.blockIpExact(
                            normalized,
                            "blacklist"
                    );
        } else {
            try {
                InetAddress address =
                        InetAddress.getByName(
                                normalized
                        );

                IpCidr matchedCidr =
                        ipPrefixIndex.findMatch(
                                address
                        ).orElse(
                                null
                        );

                decision =
                        matchedCidr == null
                                ? BlockDecision.allow()
                                : BlockDecision.blockIpCidr(
                                matchedCidr.toString(),
                                "blacklist"
                        );

            } catch (Exception e) {
                logger.debug(
                        "Unable to check IP against CIDR index: {}",
                        normalized,
                        e
                );

                decision =
                        BlockDecision.allow();
            }
        }

        putCache(
                ipCache,
                normalized,
                decision,
                maxIpCacheSize
        );

        return decision;
    }

    public BlockDecision checkDomain(
            String domain
    ) {
        String normalized =
                HostNormalizer.normalizeHost(
                        domain
                );

        if (normalized == null) {
            return BlockDecision.allow();
        }

        CacheEntry cached =
                domainCache.get(
                        normalized
                );

        if (cached != null) {
            if (
                    !cached.expired(
                            cacheTtlMillis
                    )
            ) {
                return cached.decision;
            }

            domainCache.remove(
                    normalized,
                    cached
            );
        }

        BlockDecision decision =
                domainTrie.matches(
                        normalized
                )
                        ? BlockDecision.blockDomain(
                        DomainTrie.MatchType.SUBTREE,
                        normalized,
                        "blacklist"
                )
                        : BlockDecision.allow();

        putCache(
                domainCache,
                normalized,
                decision,
                maxDomainCacheSize
        );

        return decision;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public int getIpRuleCount() {
        return exactIps.size();
    }

    public int getCidrRuleCount() {
        return cidrs.size();
    }

    public int getDomainRuleCount() {
        return domainTrie.size();
    }

    private static Set<String> immutableIpSet(
            Set<String> values
    ) {
        Set<String> result =
                ConcurrentHashMap.newKeySet();

        if (values != null) {
            for (String value : values) {
                String normalized =
                        HostNormalizer.normalizeIp(
                                value
                        );

                if (normalized != null) {
                    result.add(normalized);
                }
            }
        }

        return Collections.unmodifiableSet(
                result
        );
    }

    private static Set<IpCidr> immutableCidrSet(
            Set<IpCidr> values
    ) {
        Set<IpCidr> result =
                ConcurrentHashMap.newKeySet();

        if (values != null) {
            result.addAll(
                    values
            );
        }

        return Collections.unmodifiableSet(
                result
        );
    }

    private static Map<String, CacheEntry> createLruCache(
            int maxSize
    ) {
        return Collections.synchronizedMap(
                new LinkedHashMap<>(
                        16,
                        0.75f,
                        true
                ) {
                    @Override
                    protected boolean removeEldestEntry(
                            Map.Entry<
                                    String,
                                    CacheEntry
                                    > eldest
                    ) {
                        return size() > maxSize;
                    }
                }
        );
    }

    private static void putCache(
            Map<String, CacheEntry> cache,
            String key,
            BlockDecision decision,
            int maxSize
    ) {
        synchronized (cache) {
            cache.put(
                    key,
                    new CacheEntry(
                            decision
                    )
            );

            if (cache.size() > maxSize) {
                cache.remove(
                        cache.keySet()
                                .iterator()
                                .next()
                );
            }
        }
    }

    private static AppConfig safeConfig() {
        try {
            return Main.getConfig();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static int positiveInt(
            AppConfig config,
            String key,
            int fallback
    ) {
        if (config == null) {
            return fallback;
        }

        try {
            return Math.max(
                    1,
                    config.getInt(
                            key
                    )
            );
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    private static long positiveLong(
            AppConfig config,
            String key,
            long fallback
    ) {
        if (config == null) {
            return fallback;
        }

        try {
            return Math.max(
                    1L,
                    config.getLong(
                            key
                    )
            );
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    private static final class CacheEntry {
        private final BlockDecision decision;
        private final long createdAt =
                System.currentTimeMillis();

        private CacheEntry(
                BlockDecision decision
        ) {
            this.decision = decision;
        }

        private boolean expired(
                long ttlMillis
        ) {
            return System.currentTimeMillis()
                    - createdAt
                    >= ttlMillis;
        }
    }
}