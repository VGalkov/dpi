package ru.galkov.util;

import java.net.*;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * Утилиты безопасности: проверка URL, localhost, private ranges, cloud metadata.
 */
public final class SecurityUtil {

    private SecurityUtil() {}

    public static boolean isLocalHost(String host) {
        return "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host)
                || "::1".equals(host)
                || "[::1]".equals(host);
    }

    public static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) return isBlockedAddressUncheckedIpv4(bytes);
        if (address instanceof Inet6Address)
            return isUniqueLocalIpv6(bytes) || isIpv4MappedBlockedAddress(bytes);

        return false;
    }

    public static boolean isBlockedAddressUncheckedIpv4(byte[] bytes) {
        if (bytes == null || bytes.length != 4) return false;
        int a = bytes[0] & 0xff, b = bytes[1] & 0xff;
        if (a == 0 || a == 10 || a == 127) return true;
        if (a == 169 && b == 254) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 192 && b == 168) return true;
        if (a == 100 && b >= 64 && b <= 127) return true;
        if (a == 100 && b == 100) {
            int c = bytes[2] & 0xff, d = bytes[3] & 0xff;
            return c == 100 && d == 200;
        }
        return false;
    }

    public static boolean isUniqueLocalIpv6(byte[] bytes) {
        if (bytes.length != 16) return false;
        int first = bytes[0] & 0xff;
        return first >= 0xfc && first <= 0xfd;
    }

    public static boolean isIpv4MappedBlockedAddress(byte[] bytes) {
        if (bytes.length != 16) return false;
        for (int i = 0; i < 10; i++) if (bytes[i] != 0) return false;
        if (bytes[10] != (byte) 0xff || bytes[11] != (byte) 0xff) return false;
        byte[] ipv4 = { bytes[12], bytes[13], bytes[14], bytes[15] };
        return isBlockedAddressUncheckedIpv4(ipv4);
    }

    public static String validateLlmUrl(String urlString, boolean allowLocalLlm, int localLlmPort) {
        if (urlString == null || urlString.isBlank())
            throw new IllegalArgumentException(LocaleUtil.getString("security_url_null_blank"));

        try {
            URI uri = new URI(urlString);
            String scheme = uri.getScheme();
            String host = uri.getHost();

            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
                throw new IllegalArgumentException(LocaleUtil.getString("security_url_scheme_invalid"));

            if (host == null || host.isBlank())
                throw new IllegalArgumentException(LocaleUtil.getString("security_url_host_missing"));

            if (uri.getUserInfo() != null)
                throw new IllegalArgumentException(LocaleUtil.getString("security_url_user_info_not_allowed"));

            if (uri.getFragment() != null)
                throw new IllegalArgumentException(LocaleUtil.getString("security_url_fragment_not_allowed"));

            int port = uri.getPort();
            if (port == -1) port = "https".equalsIgnoreCase(scheme) ? 443 : 80;

            if (port < 1 || port > 65535)
                throw new IllegalArgumentException(LocaleUtil.getString("security_url_port_invalid"));

            if (isLocalHost(host)) {
                if (!allowLocalLlm)
                    throw new IllegalArgumentException(LocaleUtil.getString("security_url_local_disabled"));

                if (port != localLlmPort)
                    throw new IllegalArgumentException(LocaleUtil.getString("security_url_local_port_invalid", localLlmPort));

                return uri.toString();
            }

            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isBlockedAddress(address))
                    throw new IllegalArgumentException(LocaleUtil.getString("security_url_blocked_address", address.getHostAddress()));
            }

            return uri.toString();
        } catch (URISyntaxException | UnknownHostException e) {
            throw new IllegalArgumentException(LocaleUtil.getString("security_url_invalid_or_unresolved"), e);
        }
    }
}