package ru.galkov.util;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class IpPrefixIndexTest {
    @Test
    void matchesSpecificAndWildcardIpv4Cidrs() throws Exception {
        IpCidr broad = new IpCidr("10.0.0.0/8");
        IpCidr specific = new IpCidr("10.10.0.0/16");
        IpPrefixIndex index = IpPrefixIndex.build(List.of(broad, specific));

        assertEquals(specific, index.findMatch("10.10.1.1").orElseThrow());
        assertEquals(broad, index.findMatch("10.20.1.1").orElseThrow());
        assertTrue(index.contains("10.10.1.1"));
        assertFalse(index.contains("11.10.1.1"));
    }

    @Test
    void matchesIpv4ZeroPrefix() throws Exception {
        IpCidr cidr = new IpCidr("0.0.0.0/0");
        IpPrefixIndex index = IpPrefixIndex.build(List.of(cidr));
        assertEquals(cidr, index.findMatch("8.8.8.8").orElseThrow());
    }

    @Test
    void matchesIpv6ZeroAndSpecificPrefixes() throws Exception {
        IpCidr broad = new IpCidr("::/0");
        IpCidr specific = new IpCidr("2001:db8::/32");
        IpPrefixIndex index = IpPrefixIndex.build(List.of(broad, specific));

        assertEquals(specific, index.findMatch("2001:db8::1").orElseThrow());
        assertEquals(broad, index.findMatch("2001:4860:4860::8888").orElseThrow());
        assertFalse(index.contains("8.8.8.8"));
    }

    @Test
    void doesNotResolveHostname() throws Exception {
        IpPrefixIndex index = IpPrefixIndex.build(List.of(new IpCidr("0.0.0.0/0")));
        assertTrue(index.findMatch("8.8.8.8").isPresent());
        assertTrue(index.findMatch("example.com").isEmpty());
    }
}
