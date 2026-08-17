package ru.galkov.util;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * Модель IP-сети в CIDR для IPv4 и IPv6.
 */
public final class IpCidr {

    private final InetAddress network;
    private final int prefixLength;
    private final byte[] networkBytes;
    private final byte[] maskBytes;

    public IpCidr(String cidr) throws UnknownHostException {
        int slash = cidr.indexOf('/');

        if (slash <= 0 || slash == cidr.length() - 1)
            throw new UnknownHostException(LocaleUtil.getString("invalid_cidr", cidr));

        String ipPart = cidr.substring(0, slash);
        String prefixPart = cidr.substring(slash + 1);

        this.network = InetAddress.getByName(ipPart);
        this.prefixLength = Integer.parseInt(prefixPart);

        int maxPrefix = this.network.getAddress().length == 4 ? 32 : 128;

        if (prefixLength < 0 || prefixLength > maxPrefix)
            throw new UnknownHostException(LocaleUtil.getString("prefix_out_of_range", maxPrefix, cidr));

        this.networkBytes = this.network.getAddress();
        this.maskBytes = createMask(this.network.getAddress().length, prefixLength);
    }

    private static byte[] createMask(int length, int prefixLength) {
        byte[] mask = new byte[length];

        for (int i = 0; i < length; i++) {
            int bits = Math.max(0, prefixLength - i * 8);
            bits = Math.min(8, bits);
            mask[i] = (byte) (0xFF << (8 - bits));
        }

        return mask;
    }

    public boolean contains(InetAddress address) {
        if (address.getAddress().length != networkBytes.length)
            return false;

        byte[] addrBytes = address.getAddress();

        for (int i = 0; i < networkBytes.length; i++) {
            if ((addrBytes[i] & maskBytes[i]) != (networkBytes[i] & maskBytes[i]))
                return false;
        }

        return true;
    }

    public boolean contains(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            return contains(address);
        } catch (UnknownHostException e) {
            return false;
        }
    }

}