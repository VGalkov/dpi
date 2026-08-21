package ru.galkov.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class IpCidr {
    private final InetAddress network;
    private final int prefixLength;
    private final byte[] networkBytes;
    private final byte[] maskBytes;

    private static final int MAX_CACHE_SIZE = 512;

    private static final Map<String, InetAddress> addressCache =
            Collections.synchronizedMap(
                    new LinkedHashMap<String, InetAddress>(256, 0.75f, true) {
                        @Override
                        protected boolean removeEldestEntry(
                                Map.Entry<String, InetAddress> eldest) {
                            return size() > MAX_CACHE_SIZE;
                        }
                    }
            );

    public IpCidr(String cidr) throws UnknownHostException {
        if (cidr == null || cidr.isEmpty()) {
            throw new UnknownHostException(
                    LocaleUtil.getString("invalid_cidr", cidr)
            );
        }

        int slash = cidr.indexOf('/');
        if (slash <= 0 || slash == cidr.length() - 1) {
            throw new UnknownHostException(
                    LocaleUtil.getString("invalid_cidr", cidr)
            );
        }

        this.network = InetAddress.getByName(cidr.substring(0, slash));
        this.prefixLength = Integer.parseInt(cidr.substring(slash + 1));

        int maxPrefix = this.network.getAddress().length == 4 ? 32 : 128;
        if (prefixLength < 0 || prefixLength > maxPrefix) {
            throw new UnknownHostException(
                    LocaleUtil.getString("prefix_out_of_range", maxPrefix, cidr)
            );
        }

        this.networkBytes = this.network.getAddress();

        if (this.networkBytes.length == 0) {
            throw new UnknownHostException(
                    LocaleUtil.getString("invalid_cidr", cidr)
            );
        }

        this.maskBytes = createMask(this.networkBytes.length, prefixLength);
    }

    private static byte[] createMask(int length, int prefixLength) {
        byte[] mask = new byte[length];
        for (int i = 0; i < length; i++) {
            int bits = prefixLength - i * 8;
            if (bits >= 8) {
                mask[i] = (byte) 0xFF;
            } else if (bits <= 0) {
                mask[i] = 0;
            } else {
                mask[i] = (byte) (0xFF << (8 - bits));
            }
        }
        return mask;
    }

    private static InetAddress getCachedAddress(String ip) throws UnknownHostException {
        InetAddress cached = addressCache.get(ip);
        if (cached != null) {
            return cached;
        }

        InetAddress address = InetAddress.getByName(ip);

        synchronized (addressCache) {
            if (!addressCache.containsKey(ip)) {
                addressCache.put(ip, address);
            }
        }

        return address;
    }

    public boolean contains(String ip) {
        if (ip == null) {
            return false;
        }

        try {
            InetAddress address = getCachedAddress(ip);
            return contains(address);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public boolean contains(InetAddress address) {
        if (address == null) {
            return false;
        }

        byte[] addr = address.getAddress();
        if (addr == null || addr.length != networkBytes.length) {
            return false;
        }

        for (int i = 0; i < networkBytes.length; i++) {
            if ((addr[i] & maskBytes[i]) != (networkBytes[i] & maskBytes[i])) {
                return false;
            }
        }
        return true;
    }

    public static boolean isBlockedAddressUncheckedIpv4(byte[] bytes) {
        int a = bytes[0] & 0xff;
        int b = bytes[1] & 0xff;
        int c = bytes[2] & 0xff;
        int d = bytes[3] & 0xff;

        return a == 0
                || a == 10
                || (a == 127)
                || (a == 169 && b == 254)
                || (a == 172 && b >= 16 && b <= 31)
                || (a == 192 && b == 168)
                || (a == 100 && b >= 64 && b <= 127)
                || (a == 169 && b == 254 && c == 169 && d == 254)
                || (a == 100 && b == 100 && c == 100 && d == 200);
    }

    @Override
    public String toString() {
        return network.getHostAddress() + "/" + prefixLength;
    }
}