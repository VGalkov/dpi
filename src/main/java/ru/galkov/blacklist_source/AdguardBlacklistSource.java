package ru.galkov.blacklist_source;

import ru.galkov.util.BlacklistRule;
import ru.galkov.util.LocaleUtil;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.util.List;
import java.util.Locale;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class AdguardBlacklistSource extends AbstractBlacklistSource {
    private static final int MAX_REDIRECTS = 3;
    private static final int MAX_LINE_LENGTH = 16_384;
    private static final long MAX_RESPONSE_BYTES = 100L * 1024L * 1024L;

    private final String url;
    private final int connectTimeout;
    private final int readTimeout;

    public AdguardBlacklistSource(String url, int connectTimeout, int readTimeout) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("AdGuard URL cannot be null or blank");
        }
        if (connectTimeout <= 0) {
            throw new IllegalArgumentException("connectTimeout must be positive");
        }
        if (readTimeout <= 0) {
            throw new IllegalArgumentException("readTimeout must be positive");
        }

        validateUrl(url);

        this.url = url;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    @Override
    public List<BlacklistRule> loadRules() throws IOException {
        logger.info(LocaleUtil.getString("adguard_load_started"), url);

        HttpURLConnection connection = null;

        try {
            connection = openConnection(url);

            int status = connection.getResponseCode();
            logger.info(LocaleUtil.getString("adguard_http_response"), status);

            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException(
                        LocaleUtil.getString("adguard_http_error") + status);
            }

            long contentLength = connection.getContentLengthLong();
            if (contentLength > MAX_RESPONSE_BYTES) {
                throw new IOException("AdGuard response is too large: " + contentLength);
            }

            try (InputStream input = new LimitedInputStream(
                    connection.getInputStream(),
                    MAX_RESPONSE_BYTES)) {

                List<BlacklistRule> rules = loadFromStream(input, "AdGuard");
                logger.info(
                        LocaleUtil.getString("adguard_blacklist_loaded"),
                        rules.size()
                );
                return rules;
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private HttpURLConnection openConnection(String sourceUrl) throws IOException {
        String currentUrl = sourceUrl;

        for (int redirect = 0; redirect <= MAX_REDIRECTS; redirect++) {
            URL parsedUrl = parseHttpUrl(currentUrl);

            HttpURLConnection connection =
                    (HttpURLConnection) parsedUrl.openConnection();

            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(connectTimeout);
            connection.setReadTimeout(readTimeout);
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setRequestProperty("Accept", "text/plain, */*");
            connection.setRequestProperty("User-Agent", "Galkov-DnsProxy/1.0");

            int status = connection.getResponseCode();

            if (!isRedirect(status)) {
                return connection;
            }

            String location = connection.getHeaderField("Location");
            connection.disconnect();

            if (location == null || location.isBlank()) {
                throw new IOException("Redirect response has no Location header");
            }

            currentUrl = resolveRedirect(currentUrl, location);
        }

        throw new IOException("Too many redirects");
    }

    private static URL parseHttpUrl(String value) throws IOException {
        try {
            URI uri = new URI(value);

            validateUri(uri);

            String host = uri.getHost();
            ensureHostIsSafe(host);

            return uri.toURL();
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new IOException("Invalid HTTP URL", e);
        }
    }

    private static void validateUrl(String value) {
        try {
            URI uri = new URI(value);
            validateUri(uri);
            ensureHostIsSafe(uri.getHost());
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid AdGuard URL", e);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unsafe AdGuard URL", e);
        }
    }

    private static void validateUri(URI uri) throws IOException {
        String scheme = uri.getScheme();

        if (!"http".equalsIgnoreCase(scheme)
                && !"https".equalsIgnoreCase(scheme)) {
            throw new IOException("Only HTTP and HTTPS URLs are allowed");
        }

        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IOException("URL host is missing");
        }

        if (uri.getUserInfo() != null) {
            throw new IOException("URL user info is not allowed");
        }

        if (uri.getFragment() != null) {
            throw new IOException("URL fragments are not allowed");
        }

        int port = uri.getPort();
        if (port != -1 && (port < 1 || port > 65535)) {
            throw new IOException("Invalid URL port");
        }
    }

    private static void ensureHostIsSafe(String host) throws IOException {
        if (host == null || host.isBlank()) {
            throw new IOException("Host is missing");
        }

        if ("localhost".equalsIgnoreCase(host)) {
            throw new IOException("Localhost URL is not allowed");
        }

        InetAddress[] addresses = InetAddress.getAllByName(host);

        if (addresses.length == 0) {
            throw new IOException("Host has no resolved addresses");
        }

        for (InetAddress address : addresses) {
            if (isBlockedAddress(address)) {
                throw new IOException(
                        "URL resolves to blocked address: "
                                + address.getHostAddress());
            }
        }
    }

    private static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        byte[] bytes = address.getAddress();

        if (bytes.length == 4) {
            int a = bytes[0] & 0xff;
            int b = bytes[1] & 0xff;
            int c = bytes[2] & 0xff;
            int d = bytes[3] & 0xff;

            if (a == 169 && b == 254 && c == 169 && d == 254) {
                return true;
            }

            if (a == 100 && b == 100 && c == 100 && d == 200) {
                return true;
            }

            if (a == 100 && b >= 64 && b <= 127) {
                return true;
            }

            return a == 0;
        }

        if (address instanceof Inet6Address) {
            return isUniqueLocalIpv6(bytes)
                    || isIpv4MappedBlockedAddress(bytes);
        }

        return false;
    }

    private static boolean isUniqueLocalIpv6(byte[] bytes) {
        return bytes.length == 16
                && (bytes[0] & 0xff) >= 0xfc
                && (bytes[0] & 0xff) <= 0xfd;
    }

    private static boolean isIpv4MappedBlockedAddress(byte[] bytes) {
        if (bytes.length != 16) {
            return false;
        }

        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }

        if (bytes[10] != (byte) 0xff || bytes[11] != (byte) 0xff) {
            return false;
        }

        byte[] ipv4 = new byte[] {
                bytes[12], bytes[13], bytes[14], bytes[15]
        };

        return isBlockedAddressUncheckedIpv4(ipv4);
    }

    private static boolean isBlockedAddressUncheckedIpv4(byte[] bytes) {
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

    private static String resolveRedirect(String currentUrl, String location)
            throws IOException {
        try {
            URI current = new URI(currentUrl);
            URI resolved = current.resolve(location);

            validateUri(resolved);
            ensureHostIsSafe(resolved.getHost());

            return resolved.toString();
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new IOException("Invalid redirect URL", e);
        }
    }

    private static boolean isRedirect(int status) {
        return status == HttpURLConnection.HTTP_MOVED_PERM
                || status == HttpURLConnection.HTTP_MOVED_TEMP
                || status == HttpURLConnection.HTTP_SEE_OTHER
                || status == 307
                || status == 308;
    }

    @Override
    protected BlacklistRule parseLine(String line, String sourceName) {
        if (line == null || line.length() > MAX_LINE_LENGTH) {
            return null;
        }

        String value = line.trim();

        if (value.isEmpty()
                || value.startsWith("#")
                || value.startsWith("!")) {
            return null;
        }

        if (value.startsWith("||")) {
            value = parseAdguardDomain(value);
        } else {
            value = parseHostsLine(value);
        }

        if (value == null || !isValidDomainCandidate(value)) {
            return null;
        }

        return new BlacklistRule(
                BlacklistRule.RuleType.DOMAIN,
                value.toLowerCase(Locale.ROOT),
                sourceName,
                null,
                null
        );
    }

    private static String parseAdguardDomain(String value) {
        value = value.substring(2);

        int separator = value.indexOf('^');
        int modifier = value.indexOf('$');

        int end = value.length();

        if (separator >= 0) {
            end = Math.min(end, separator);
        }

        if (modifier >= 0) {
            end = Math.min(end, modifier);
        }

        value = value.substring(0, end);

        int slash = value.indexOf('/');
        if (slash >= 0) {
            value = value.substring(0, slash);
        }

        return value.trim();
    }

    private static String parseHostsLine(String value) {
        String[] parts = value.split("\\s+");

        if (parts.length < 2 || !isIpLiteral(parts[0])) {
            return value;
        }

        return parts[1].trim();
    }

    // ✅ П.15: ручная проверка вместо DNS-резолва (InetAddress.getByName)
    private static boolean isIpLiteral(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }

        if (value.indexOf(':') >= 0) {
            return isIpv6Literal(value);
        }

        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }

            try {
                int number = Integer.parseInt(part);
                if (number < 0 || number > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

    private static boolean isIpv6Literal(String value) {
        if (value.isEmpty()) {
            return false;
        }

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c == ':'
                    || (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }

        return true;
    }

    private static boolean isValidDomainCandidate(String value) {
        if (value == null
                || value.isEmpty()
                || value.length() > 253
                || value.contains("://")
                || value.contains("@")
                || value.contains("?")
                || value.contains("=")
                || value.contains("%")
                || value.contains("*")
                || value.startsWith(".")
                || value.endsWith(".")
                || value.startsWith("-")
                || value.endsWith("-")) {
            return false;
        }

        String[] labels = value.split("\\.", -1);

        for (String label : labels) {
            if (label.isEmpty()
                    || label.length() > 63
                    || label.startsWith("-")
                    || label.endsWith("-")) {
                return false;
            }

            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);

                if (!(Character.isLetterOrDigit(c)
                        || c == '-'
                        || c == '_')) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public String toString() {
        return "AdguardBlacklistSource{url='" + url + "'}";
    }

    private static final class LimitedInputStream extends FilterInputStream {
        private final long maxBytes;
        private long totalBytes;

        private LimitedInputStream(InputStream input, long maxBytes) {
            super(input);
            this.maxBytes = maxBytes;
        }

        @Override
        public int read() throws IOException {
            ensureCapacity(1);

            int value = super.read();
            if (value >= 0) {
                totalBytes++;
            }

            return value;
        }

        // ✅ Исправлено: не читаем сверх оставшегося лимита за один вызов
        @Override
        public int read(byte[] buffer, int offset, int length)
                throws IOException {
            if (length == 0) {
                return 0;
            }

            long remaining = maxBytes - totalBytes;
            if (remaining <= 0) {
                throw new IOException("AdGuard response exceeds maximum size");
            }

            int toRead = (int) Math.min(length, remaining);
            int read = super.read(buffer, offset, toRead);
            if (read > 0) {
                totalBytes += read;
            }

            return read;
        }

        private void ensureCapacity(long requested) throws IOException {
            if (totalBytes >= maxBytes || requested > maxBytes - totalBytes) {
                throw new IOException("AdGuard response exceeds maximum size");
            }
        }
    }
}