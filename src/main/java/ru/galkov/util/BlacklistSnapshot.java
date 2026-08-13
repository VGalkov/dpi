package ru.galkov.util;

import ru.galkov.DomainTrie;

import java.util.Collections;
import java.util.Set;

public final class BlacklistSnapshot {

    private final DomainTrie domainTrie;
    private final Set<String> ips;

    public BlacklistSnapshot(DomainTrie domainTrie, Set<String> ips) {
        this.domainTrie = domainTrie;
        this.ips = ips;
    }

    /**
     * Проверяет, заблокирован ли домен (включая поддомены).
     */
    public boolean matchesDomain(String domain) {
        return domainTrie.isBlocked(domain);
    }

    /**
     * Проверяет, заблокирован ли IP.
     */
    public boolean containsIp(String ip) {
        return ips.contains(ip);
    }

    public static BlacklistSnapshot empty() {
        return new BlacklistSnapshot(new DomainTrie(), Collections.emptySet());
    }
}