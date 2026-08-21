package ru.galkov.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class HostNormalizerTest {
    @BeforeAll
    static void beforeAll() {
        log("=".repeat(80));
        log("START HostNormalizerTest");
        log("Java version: " + System.getProperty("java.version"));
        log(
                "OS: "
                        + System.getProperty("os.name")
                        + " "
                        + System.getProperty("os.version")
        );
        log("=".repeat(80));
    }

    @Test
    @DisplayName("IPv4 normalization and strict parsing")
    void normalizesValidIpv4WithoutDnsLookup(
            TestInfo testInfo
    ) {
        begin(testInfo);

        assertNormalizedIp(
                " 8.8.8.8 ",
                "8.8.8.8"
        );

        assertNormalizedIp(
                "192.168.1.1",
                "192.168.1.1"
        );

        assertNormalizedIp(
                "0.0.0.0",
                "0.0.0.0"
        );

        assertNormalizedIp(
                "255.255.255.255",
                "255.255.255.255"
        );

        log("IPv4 valid cases passed");
        end(testInfo);
    }

    @Test
    @DisplayName("Invalid IPv4 and hostnames are rejected as IP")
    void rejectsInvalidIpv4AndHostnamesAsIp(
            TestInfo testInfo
    ) {
        begin(testInfo);

        assertNullIp("8.8.8.999");
        assertNullIp("256.0.0.1");
        assertNullIp("8.8.8");
        assertNullIp("8.8.8.8.8");
        assertNullIp("8.8..8");
        assertNullIp("08.08.08.08");
        assertNullIp("001.2.3.4");
        assertNullIp("1.002.3.4");
        assertNullIp("example.com");
        assertNullIp("hostname/24");
        assertNullIp("127.0.0.1/32");
        assertNullIp(" 8.8.8.8 extra ");

        log(
                "Invalid IPv4, hostname and CIDR-as-IP "
                        + "cases passed"
        );

        end(testInfo);
    }

    @Test
    @DisplayName("IPv6 normalization and compressed notation")
    void normalizesValidIpv6(
            TestInfo testInfo
    ) {
        begin(testInfo);

        assertNormalizedIp(
                "2001:db8::1",
                "2001:db8::1"
        );

        assertNormalizedIp(
                "2001:db8::",
                "2001:db8::"
        );

        assertNormalizedIp(
                "::1",
                "::1"
        );

        assertNormalizedIp(
                "::",
                "::"
        );

        assertNormalizedIp(
                "2001:0DB8:0000:0000:0000:0000:0000:0001",
                "2001:db8::1"
        );

        assertNormalizedIp(
                "::ffff:192.0.2.128",
                "::ffff:c000:280"
        );

        log("IPv6 valid cases passed");
        end(testInfo);
    }

    @Test
    @DisplayName("Invalid IPv6 is rejected")
    void rejectsInvalidIpv6(
            TestInfo testInfo
    ) {
        begin(testInfo);

        assertNullIp("2001:::1");
        assertNullIp("2001:db8::1::");
        assertNullIp("2001:db8:zz::1");
        assertNullIp("2001:db8:1:2:3:4:5:6:7");
        assertNullIp("2001:db8:1:2:3:4:5");
        assertNullIp("2001:db8::1%eth0");
        assertNullIp("[2001:db8::1]");
        assertNullIp("2001:db8::1/128");
        assertNullIp("hostname");

        log("Invalid IPv6 cases passed");
        end(testInfo);
    }

    @Test
    @DisplayName("DNS host normalization")
    void validatesDnsHosts(
            TestInfo testInfo
    ) {
        begin(testInfo);

        assertNormalizedHost(
                "Example.COM.",
                "example.com"
        );

        assertNormalizedHost(
                "WWW.Example.COM",
                "www.example.com"
        );

        assertNormalizedHost(
                "localhost",
                "localhost"
        );

        assertNullHost("-example.com");
        assertNullHost("example-.com");
        assertNullHost("example..com");
        assertNullHost(".example.com");
        assertNullHost("example.com/path");
        assertNullHost("example.com:443");
        assertNullHost("example.com host");
        assertNullHost("example_com");
        assertNullHost("hostname/24");

        log(
                "DNS host normalization and validation "
                        + "cases passed"
        );

        end(testInfo);
    }

    @Test
    @DisplayName("Host and port parsing")
    void parsesHostPort(
            TestInfo testInfo
    ) {
        begin(testInfo);

        assertHostPort(
                "example.com:443",
                "example.com",
                443
        );

        assertHostPort(
                "EXAMPLE.COM.:80",
                "example.com",
                80
        );

        assertHostPort(
                "8.8.8.8:53",
                "8.8.8.8",
                53
        );

        assertHostPort(
                "[2001:db8::1]:443",
                "2001:db8::1",
                443
        );

        assertHostPort(
                "[::1]:53",
                "::1",
                53
        );

        assertNullHostPort(
                "2001:db8::1:443"
        );

        assertNullHostPort(
                "example.com:0"
        );

        assertNullHostPort(
                "example.com:65536"
        );

        assertNullHostPort(
                "example.com:not-a-port"
        );

        assertNullHostPort(
                "[2001:db8::1]443"
        );

        assertNullHostPort(
                "[]:443"
        );

        assertNullHostPort(
                "example.com"
        );

        log("Host:port parsing cases passed");
        end(testInfo);
    }

    @Test
    @DisplayName("Low-level parser returns expected byte lengths")
    void parsesIpLiteralBytes(
            TestInfo testInfo
    ) {
        begin(testInfo);

        byte[] ipv4 =
                HostNormalizer.parseIpLiteral(
                        "192.168.1.10"
                );

        log(
                "IPv4 bytes: "
                        + Arrays.toString(ipv4)
        );

        assertTrue(
                ipv4 != null
                        && ipv4.length == 4
        );

        byte[] ipv6 =
                HostNormalizer.parseIpLiteral(
                        "2001:db8::1"
                );

        log(
                "IPv6 bytes: "
                        + Arrays.toString(ipv6)
        );

        assertTrue(
                ipv6 != null
                        && ipv6.length == 16
        );

        boolean ipv4Literal =
                HostNormalizer.isIpLiteralFast(
                        "192.168.1.10"
                );

        log(
                "isIpLiteralFast('192.168.1.10') = "
                        + ipv4Literal
        );

        assertTrue(ipv4Literal);

        boolean ipv6Literal =
                HostNormalizer.isIpv6LiteralFast(
                        "2001:db8::1"
                );

        log(
                "isIpv6LiteralFast('2001:db8::1') = "
                        + ipv6Literal
        );

        assertTrue(ipv6Literal);

        boolean hostnameLiteral =
                HostNormalizer.isIpLiteralFast(
                        "example.com"
                );

        log(
                "isIpLiteralFast('example.com') = "
                        + hostnameLiteral
        );

        assertTrue(!hostnameLiteral);

        log("Low-level parser checks passed");
        end(testInfo);
    }

    private static void assertNormalizedIp(
            String input,
            String expected
    ) {
        String actual =
                HostNormalizer.normalizeIp(
                        input
                );

        log(
                "normalizeIp: input='"
                        + input
                        + "', expected='"
                        + expected
                        + "', actual='"
                        + actual
                        + "'"
        );

        assertEquals(
                expected,
                actual
        );
    }

    private static void assertNullIp(
            String input
    ) {
        String actual =
                HostNormalizer.normalizeIp(
                        input
                );

        log(
                "normalizeIp rejected: input='"
                        + input
                        + "', actual='"
                        + actual
                        + "'"
        );

        assertNull(actual);
    }

    private static void assertNormalizedHost(
            String input,
            String expected
    ) {
        String actual =
                HostNormalizer.normalizeHost(
                        input
                );

        log(
                "normalizeHost: input='"
                        + input
                        + "', expected='"
                        + expected
                        + "', actual='"
                        + actual
                        + "'"
        );

        assertEquals(
                expected,
                actual
        );
    }

    private static void assertNullHost(
            String input
    ) {
        String actual =
                HostNormalizer.normalizeHost(
                        input
                );

        log(
                "normalizeHost rejected: input='"
                        + input
                        + "', actual='"
                        + actual
                        + "'"
        );

        assertNull(actual);
    }

    private static void assertHostPort(
            String input,
            String expectedHost,
            int expectedPort
    ) {
        HostNormalizer.HostAndPort actual =
                HostNormalizer.parseHostPort(
                        input
                );

        log(
                "parseHostPort: input='"
                        + input
                        + "', actual='"
                        + actual
                        + "'"
        );

        assertEquals(
                new HostNormalizer.HostAndPort(
                        expectedHost,
                        expectedPort
                ),
                actual
        );
    }

    private static void assertNullHostPort(
            String input
    ) {
        HostNormalizer.HostAndPort actual =
                HostNormalizer.parseHostPort(
                        input
                );

        log(
                "parseHostPort rejected: input='"
                        + input
                        + "', actual='"
                        + actual
                        + "'"
        );

        assertNull(actual);
    }

    private static void begin(
            TestInfo testInfo
    ) {
        log("");
        log(
                "--- TEST START: "
                        + testInfo.getDisplayName()
                        + " ---"
        );
    }

    private static void end(
            TestInfo testInfo
    ) {
        log(
                "--- TEST PASS: "
                        + testInfo.getDisplayName()
                        + " ---"
        );

        log("");
    }

    private static void log(
            String message
    ) {
        System.out.println(
                "[HostNormalizerTest] "
                        + message
        );
    }
}