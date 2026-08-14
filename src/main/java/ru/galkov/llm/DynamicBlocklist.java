package ru.galkov.llm;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class DynamicBlocklist {

    private final ConcurrentMap<String, Long> blockedDomains = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Long> blockedClients = new ConcurrentHashMap<>();
    private final long ttlMillis;

    public DynamicBlocklist(long ttlMinutes) {
        this.ttlMillis = ttlMinutes * 60 * 1000;
    }

    public void addDomain(String domain, long expireAt) {
        blockedDomains.put(domain, expireAt);
    }

    public void addClientIp(String ip, long expireAt) {
        blockedClients.put(ip, expireAt);
    }

    public boolean containsDomain(String domain) {
        cleanup();
        return blockedDomains.containsKey(domain);
    }

    public boolean containsClientIp(String ip) {
        cleanup();
        return blockedClients.containsKey(ip);
    }

    private void cleanup() {
        long now = System.currentTimeMillis();
        blockedDomains.entrySet().removeIf(e -> e.getValue() < now);
        blockedClients.entrySet().removeIf(e -> e.getValue() < now);
    }
}