package ru.galkov.servers;

import java.util.Collections;
import java.util.Set;

public final class BlacklistSnapshot {

    private final Set<String> domains;
    private final Set<String> ips;

    public BlacklistSnapshot(
            Set<String> domains,
            Set<String> ips) {

        this.domains =
                Collections.unmodifiableSet(domains);

        this.ips =
                Collections.unmodifiableSet(ips);
    }

    public static BlacklistSnapshot empty() {
        return new BlacklistSnapshot(
                Collections.<String>emptySet(),
                Collections.<String>emptySet()
        );
    }

    public Set<String> domains() {
        return domains;
    }

    public Set<String> ips() {
        return ips;
    }

    public boolean matchesDomain(
            String domain) {

        String current =
                domain;

        while (true) {
            if (domains.contains(current)) {
                return true;
            }

            int dot =
                    current.indexOf('.');

            if (dot < 0) {
                return false;
            }

            current =
                    current.substring(dot + 1);
        }
    }
}