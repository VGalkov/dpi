package ru.galkov.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class IpCidr {
    private final InetAddress network;
    private final int prefixLength;
    private final byte[] networkBytes;
    private final byte[] maskBytes;

    private static final Map<String, InetAddress> addressCache = new ConcurrentHashMap<>(256);
    private static final int MAX_CACHE_SIZE = 512;

    public IpCidr(String cidr) throws UnknownHostException {
        if (cidr == null || cidr.isEmpty()) throw new UnknownHostException(LocaleUtil.getString("invalid_cidr", cidr));
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
            // ✅ П.12: Проверка кэша с ограничением размера
            InetAddress address = addressCache.get(ip);
            if (address == null) {
                address = InetAddress.getByName(ip);
                // ✅ П.12: Ограничение размера кэша
                if (addressCache.size() >= MAX_CACHE_SIZE) {
                    addressCache.clear();
                }
                addressCache.put(ip, address);
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

    /**
     * toString() для логирования
     */
    @Override
    public String toString() {
        return String.format("%s/%d", network.getHostAddress(), prefixLength);
    }

    /**
     * Очистка кэша (вызывать при reload blacklist)
     */
    public static void clearCache() {
        addressCache.clear();
    }
}