package ru.galkov.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class HostNormalizer {
    private static final Map<String, String> ipCache = new ConcurrentHashMap<>(256);
    private static final Map<String, String> domainCache = new ConcurrentHashMap<>(256);
    private static final int MAX_CACHE_SIZE = 512;

    public static String normalizeIp(String ip) {
        if (ip == null || ip.isEmpty()) return null;
        String cached = ipCache.get(ip);
        if (cached != null) return cached;
        try {
            InetAddress addr = InetAddress.getByName(ip);
            String result = addr.getHostAddress();
            if (ipCache.size() < MAX_CACHE_SIZE) ipCache.put(ip, result);
            return result;
        } catch (UnknownHostException e) {
            return null;
        }
    }

    public static String normalizeHost(String host) {
        if (host == null || host.isEmpty()) return null;
        String cached = domainCache.get(host);
        if (cached != null) return cached;
        String result = host.toLowerCase().replaceAll("\\.$", "").trim();
        if (domainCache.size() < MAX_CACHE_SIZE) domainCache.put(host, result);
        return result;
    }

    /**
     * ✅ П.13: Очистка кэша (вызывать при reload blacklist)
     */
    public static void clearCache() {
        ipCache.clear();
        domainCache.clear();
    }
}