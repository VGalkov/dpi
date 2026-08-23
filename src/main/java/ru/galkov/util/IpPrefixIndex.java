package ru.galkov.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class IpPrefixIndex {
    private static final int IPV4_WILDCARD_BUCKET = -1;
    private static final int IPV6_WILDCARD_BUCKET = -1;
    private static final int BUCKET_BITS = 16;

    private final Map<Integer, List<IpCidr>> ipv4Buckets;
    private final Map<Integer, List<IpCidr>> ipv6Buckets;

    private IpPrefixIndex(Map<Integer, List<IpCidr>> ipv4Buckets, Map<Integer, List<IpCidr>> ipv6Buckets) {
        this.ipv4Buckets = freeze(ipv4Buckets);
        this.ipv6Buckets = freeze(ipv6Buckets);
    }

    public static IpPrefixIndex build(Collection<IpCidr> cidrs) {
        Map<Integer, List<IpCidr>> ipv4 = new HashMap<>();

        Map<Integer, List<IpCidr>> ipv6 = new HashMap<>();

        if (cidrs == null || cidrs.isEmpty())
            return new IpPrefixIndex(ipv4, ipv6);


        for (IpCidr cidr : cidrs) {
            if (cidr == null) continue;
            byte[] network = cidr.networkBytes();
            Map<Integer, List<IpCidr>> buckets = network.length == 4 ? ipv4 : ipv6;

            int prefixLength = cidr.getPrefixLength();

            if (prefixLength < BUCKET_BITS) {
                buckets.computeIfAbsent(wildcardBucket(network), ignored -> new ArrayList<>()).add(cidr);
            } else {
                buckets.computeIfAbsent(bucketKey(network), ignored -> new ArrayList<>()).add(cidr);
            }
        }
        sortCandidates(ipv4);
        sortCandidates(ipv6);
        return new IpPrefixIndex(ipv4, ipv6);
    }

    public boolean contains(InetAddress address) {
        return findMatch(address).isPresent();
    }

    public boolean contains(String ip) {
        return findMatch(ip).isPresent();
    }

    public Optional<IpCidr> findMatch(String ip) {
        if (ip == null || ip.isBlank())
            return Optional.empty();

        String normalized = ip.trim();

        if (!HostNormalizer.isIpLiteralFast(normalized))
            return Optional.empty();

        try {
            return findMatch(InetAddress.getByName(normalized));
        } catch (UnknownHostException e) {
            return Optional.empty();
        }
    }

    public Optional<IpCidr> findMatch(InetAddress address) {
        if (address == null) return Optional.empty();
        byte[] bytes = address.getAddress();
        Map<Integer, List<IpCidr>> buckets = bytes.length == 4 ? ipv4Buckets : ipv6Buckets;
        IpCidr match = findInBucket(buckets.get(bucketKey(bytes)), address);
        if (match != null) return Optional.of(match);
        match = findInBucket(buckets.get(wildcardBucket(bytes)), address);
        return match == null ? Optional.empty() : Optional.of(match);
    }

    private static IpCidr findInBucket(List<IpCidr> candidates, InetAddress address) {
        if (candidates == null) return null;

        for (IpCidr cidr : candidates) {
            if (cidr.contains(address)) return cidr;
        }

        return null;
    }

    private static void sortCandidates(Map<Integer, List<IpCidr>> buckets) {
        Comparator<IpCidr> comparator = Comparator.comparingInt(IpCidr::getPrefixLength).reversed();

        for (List<IpCidr> candidates : buckets.values()) {
            candidates.sort(comparator);
        }
    }

    private static int bucketKey(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return -1;
        return ((bytes[0] & 0xff) << 8) | (bytes[1] & 0xff);
    }

    private static int wildcardBucket(byte[] bytes) {
        return bytes != null && bytes.length == 4 ? IPV4_WILDCARD_BUCKET : IPV6_WILDCARD_BUCKET;
    }

    private static Map<Integer, List<IpCidr>> freeze(Map<Integer, List<IpCidr>> source) {
        Map<Integer, List<IpCidr>> result = new HashMap<>(source.size());
        source.forEach((key, value) -> result.put(key, List.copyOf(value)));
        return Collections.unmodifiableMap(result);
    }
}