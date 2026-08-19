package ru.galkov.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class IpCidr {
    private final InetAddress network;
    private final int prefixLength;
    private final byte[] networkBytes;
    private final byte[] maskBytes;

    private static final Map<String, InetAddress> addressCache = new ConcurrentHashMap<>(256);

    public IpCidr(String cidr) throws UnknownHostException {
        if (cidr == null || cidr.isEmpty()) throw new UnknownHostException("CIDR is null or empty");
        int slash = cidr.indexOf('/');
        if (slash <= 0 || slash == cidr.length() - 1)
            throw new UnknownHostException(LocaleUtil.getString("invalid_cidr", cidr));

        this.network = InetAddress.getByName(cidr.substring(0, slash));
        this.prefixLength = Integer.parseInt(cidr.substring(slash + 1));

        int maxPrefix = this.network.getAddress().length == 4 ? 32 : 128;
        if (prefixLength < 0 || prefixLength > maxPrefix)
            throw new UnknownHostException(LocaleUtil.getString("prefix_out_of_range", maxPrefix, cidr));

        this.networkBytes = this.network.getAddress();
        this.maskBytes = createMask(this.networkBytes.length, prefixLength);
    }

    private static byte[] createMask(int length, int prefixLength) {
        byte[] mask = new byte[length];
        for (int i = 0; i < length; i++) {
            int bits = Math.max(0, Math.min(8, prefixLength - i * 8));
            mask[i] = (byte) (0xFF << (8 - bits));
        }
        return mask;
    }

    public boolean contains(String ip) {
        try {
            // Проверка кэша
            InetAddress address = addressCache.get(ip);
            if (address == null) {
                address = InetAddress.getByName(ip);
                if (addressCache.size() < 512) {
                    addressCache.put(ip, address);
                }
            }
            return contains(address);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public boolean contains(InetAddress address) {
        if (address.getAddress().length != networkBytes.length) return false;
        byte[] addr = address.getAddress();
        for (int i = 0; i < networkBytes.length; i++)
            if ((addr[i] & maskBytes[i]) != (networkBytes[i] & maskBytes[i])) return false;
        return true;
    }
}