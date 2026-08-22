package ru.galkov.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * Immutable IPv4/IPv6 CIDR rule.
 */
public final class IpCidr {
    private final InetAddress network;
    private final int prefixLength;
    private final byte[] networkBytes;
    private final byte[] maskBytes;

    public IpCidr(String cidr) throws UnknownHostException {
        if (cidr == null || cidr.trim().isEmpty()) throw invalidCidr(cidr);
        String value = cidr.trim();
        int slash = value.indexOf('/');
        if (slash <= 0 || slash != value.lastIndexOf('/') || slash == value.length() - 1) throw invalidCidr(cidr);
        String ipPart = value.substring(0, slash).trim(), prefixPart = value.substring(slash + 1).trim();
        if (ipPart.isEmpty() || prefixPart.isEmpty()) throw invalidCidr(cidr);
        byte[] parsedAddress = HostNormalizer.parseIpLiteral(ipPart);
        if (parsedAddress == null) throw invalidCidr(cidr);
        int parsedPrefix;
        try { parsedPrefix = Integer.parseInt(prefixPart); }
        catch (NumberFormatException e) { throw invalidCidr(cidr); }
        int maxPrefix = parsedAddress.length == 4 ? 32 : 128;
        if (parsedPrefix < 0 || parsedPrefix > maxPrefix)
            throw new UnknownHostException(String.format(Locale.ROOT, "CIDR prefix must be between 0 and %d: %s", maxPrefix, cidr));
        this.prefixLength = parsedPrefix;
        this.maskBytes = createMask(parsedAddress.length, parsedPrefix);
        this.networkBytes = parsedAddress.clone();
        normalizeNetworkBytes(this.networkBytes, this.maskBytes);
        try { this.network = InetAddress.getByAddress(this.networkBytes); }
        catch (UnknownHostException e) { throw invalidCidr(cidr); }
    }

    private static UnknownHostException invalidCidr(String cidr) {
        return new UnknownHostException(String.format(Locale.ROOT, "Invalid CIDR: %s", cidr));
    }

    public boolean isIpv4() { return networkBytes.length == 4; }
    public boolean isIpv6() { return networkBytes.length == 16; }
    public int getPrefixLength() { return prefixLength; }
    public byte[] networkBytes() { return networkBytes.clone(); }

    public boolean contains(String ip) {
        if (ip == null || ip.trim().isEmpty()) return false;
        byte[] addressBytes = HostNormalizer.parseIpLiteral(ip.trim());
        return containsBytes(addressBytes);
    }

    public boolean contains(InetAddress address) {
        return address != null && containsBytes(address.getAddress());
    }

    private boolean containsBytes(byte[] addressBytes) {
        if (addressBytes == null || addressBytes.length != networkBytes.length) return false;
        for (int i = 0; i < networkBytes.length; i++) {
            if ((addressBytes[i] & maskBytes[i]) != (networkBytes[i] & maskBytes[i])) return false;
        }
        return true;
    }

    private static byte[] createMask(int length, int prefixLength) {
        byte[] mask = new byte[length];
        for (int i = 0; i < length; i++) {
            int remainingBits = prefixLength - i * 8;
            if (remainingBits >= 8) mask[i] = (byte) 0xFF;
            else if (remainingBits <= 0) mask[i] = 0;
            else mask[i] = (byte) (0xFF << (8 - remainingBits));
        }
        return mask;
    }

    private static void normalizeNetworkBytes(byte[] addressBytes, byte[] maskBytes) {
        for (int i = 0; i < addressBytes.length; i++)
            addressBytes[i] = (byte) (addressBytes[i] & maskBytes[i]);
    }

    @Override
    public String toString() {
        return network.getHostAddress().toLowerCase(Locale.ROOT) + "/" + prefixLength;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        IpCidr other = (IpCidr) obj;
        if (prefixLength != other.prefixLength) return false;
        if (networkBytes.length != other.networkBytes.length) return false;
        for (int i = 0; i < networkBytes.length; i++)
            if (networkBytes[i] != other.networkBytes[i]) return false;
        return true;
    }

    @Override
    public int hashCode() {
        int result = prefixLength;
        for (byte value : networkBytes) result = 31 * result + value;
        return result;
    }
}