package ru.galkov.util;

import org.junit.jupiter.api.Test;

import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.*;

class IpCidrTest {
    @Test
    void acceptsIpv4CidrAndNormalizesNetwork() throws Exception {
        IpCidr cidr = new IpCidr("192.168.10.77/24");
        assertEquals("192.168.10.0/24", cidr.toString());
        assertTrue(cidr.isIpv4());
        assertFalse(cidr.isIpv6());
        assertEquals(24, cidr.getPrefixLength());
        assertTrue(cidr.contains("192.168.10.1"));
        assertFalse(cidr.contains("192.168.11.1"));
    }

    @Test
    void acceptsIpv6Cidr() throws Exception {
        IpCidr cidr = new IpCidr("2001:db8::/32");
        assertEquals("2001:db8:0:0:0:0:0:0/32", cidr.toString());
        assertTrue(cidr.isIpv6());
        assertTrue(cidr.contains("2001:db8::1"));
        assertFalse(cidr.contains("2001:db9::1"));
    }

    @Test
    void acceptsZeroPrefixes() throws Exception {
        assertTrue(new IpCidr("0.0.0.0/0").contains("8.8.8.8"));
        assertTrue(new IpCidr("::/0").contains("2001:db8::1"));
    }

    @Test
    void rejectsHostnameCidr() {
        assertThrows(UnknownHostException.class, () -> new IpCidr("hostname/24"));
        assertThrows(UnknownHostException.class, () -> new IpCidr("example.com/24"));
    }

    @Test
    void rejectsInvalidPrefixesAndAddresses() {
        assertThrows(UnknownHostException.class, () -> new IpCidr("192.168.1.0/33"));
        assertThrows(UnknownHostException.class, () -> new IpCidr("2001:db8::/129"));
        assertThrows(UnknownHostException.class, () -> new IpCidr("192.168.1.999/24"));
        assertThrows(UnknownHostException.class, () -> new IpCidr("2001:::1/64"));
    }

    @Test
    void comparesCanonicalNetworks() throws Exception {
        assertEquals(new IpCidr("10.0.0.1/8"), new IpCidr("10.0.0.0/8"));
        assertEquals(new IpCidr("10.0.0.1/8").hashCode(), new IpCidr("10.0.0.0/8").hashCode());
    }
}
