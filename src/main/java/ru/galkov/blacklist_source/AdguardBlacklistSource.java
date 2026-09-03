package ru.galkov.blacklist_source;

import ru.galkov.util.BlacklistRule;
import ru.galkov.util.HostNormalizer;
import ru.galkov.util.LocaleUtil;
import ru.galkov.util.SecurityUtil;

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
        if (url == null || url.isBlank()) throw new IllegalArgumentException(LocaleUtil.getString("adguard_url_null_blank"));
        if (connectTimeout <= 0) throw new IllegalArgumentException(LocaleUtil.getString("adguard_connect_timeout_invalid"));
        if (readTimeout <= 0) throw new IllegalArgumentException(LocaleUtil.getString("adguard_read_timeout_invalid"));
        SecurityUtil.validateLlmUrl(url, true, -1);
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
            logger.debug(LocaleUtil.getString("adguard_http_response"), status);
            if (status != HttpURLConnection.HTTP_OK)
                throw new IOException(LocaleUtil.getString("adguard_http_error") + status);
            long contentLength = connection.getContentLengthLong();
            if (contentLength > MAX_RESPONSE_BYTES)
                throw new IOException(LocaleUtil.getString("adguard_response_too_large", contentLength));
            try (InputStream input = new LimitedInputStream(connection.getInputStream(), MAX_RESPONSE_BYTES)) {
                List<BlacklistRule> rules = loadFromStream(input, "AdGuard");
                logger.info(LocaleUtil.getString("adguard_blacklist_loaded"), rules.size());
                return rules;
            }
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private HttpURLConnection openConnection(String sourceUrl) throws IOException {
        String currentUrl = sourceUrl;
        for (int redirect = 0; redirect <= MAX_REDIRECTS; redirect++) {
            URL parsedUrl = parseHttpUrl(currentUrl);
            HttpURLConnection connection = getHttpURLConnection(parsedUrl);
            int status = connection.getResponseCode();
            if (!isRedirect(status)) return connection;
            String location = connection.getHeaderField("Location");
            connection.disconnect();
            if (location == null || location.isBlank())
                throw new IOException(LocaleUtil.getString("adguard_redirect_no_location"));
            currentUrl = resolveRedirect(currentUrl, location);
        }
        throw new IOException(LocaleUtil.getString("adguard_too_many_redirects"));
    }

    private HttpURLConnection getHttpURLConnection(URL parsedUrl) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) parsedUrl.openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(connectTimeout);
        connection.setReadTimeout(readTimeout);
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setRequestProperty("Accept", "text/plain, */*");
        connection.setRequestProperty("User-Agent", "Galkov-DnsProxy/1.0");
        return connection;
    }

    private static URL parseHttpUrl(String value) throws IOException {
        try {
            URI uri = new URI(value);
            validateUri(uri);
            String host = uri.getHost();
            ensureHostIsSafe(host);
            return uri.toURL();
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new IOException(LocaleUtil.getString("adguard_invalid_url"), e);
        }
    }

    private static void validateUri(URI uri) throws IOException {
        String scheme = uri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
            throw new IOException(LocaleUtil.getString("adguard_only_http_https"));
        if (uri.getHost() == null || uri.getHost().isBlank()) throw new IOException(LocaleUtil.getString("adguard_url_host_missing"));
        if (uri.getUserInfo() != null) throw new IOException(LocaleUtil.getString("adguard_url_user_info_not_allowed"));
        if (uri.getFragment() != null) throw new IOException(LocaleUtil.getString("adguard_url_fragments_not_allowed"));
        int port = uri.getPort();
        if (port != -1 && (port < 1 || port > 65535)) throw new IOException(LocaleUtil.getString("adguard_url_port_invalid"));
    }

    private static void ensureHostIsSafe(String host) throws IOException {
        if (host == null || host.isBlank()) throw new IOException(LocaleUtil.getString("adguard_host_missing"));
        if ("localhost".equalsIgnoreCase(host)) throw new IOException(LocaleUtil.getString("adguard_localhost_not_allowed"));
        InetAddress[] addresses = InetAddress.getAllByName(host);
        if (addresses.length == 0) throw new IOException(LocaleUtil.getString("adguard_no_resolved_addresses"));
        for (InetAddress address : addresses) {
            if (SecurityUtil.isBlockedAddress(address))
                throw new IOException(LocaleUtil.getString("adguard_blocked_address", address.getHostAddress()));
        }
    }

    private static String resolveRedirect(String currentUrl, String location) throws IOException {
        try {
            URI current = new URI(currentUrl);
            URI resolved = current.resolve(location);
            validateUri(resolved);
            ensureHostIsSafe(resolved.getHost());
            return resolved.toString();
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new IOException(LocaleUtil.getString("adguard_invalid_redirect"), e);
        }
    }

    private static boolean isRedirect(int status) {
        return status == HttpURLConnection.HTTP_MOVED_PERM
                || status == HttpURLConnection.HTTP_MOVED_TEMP
                || status == HttpURLConnection.HTTP_SEE_OTHER
                || status == 307 || status == 308;
    }

    @Override
    protected BlacklistRule parseLine(String line, String sourceName) {
        if (line == null || line.length() > MAX_LINE_LENGTH) return null;
        String value = line.trim();
        if (value.isEmpty() || value.startsWith("#") || value.startsWith("!")) return null;
        if (value.startsWith("||")) value = parseAdguardDomain(value);
        else value = parseHostsLine(value);
        if (!isValidDomainCandidate(value)) return null;
        return new BlacklistRule(BlacklistRule.RuleType.DOMAIN, value.toLowerCase(Locale.ROOT), sourceName, null, null);
    }

    private static String parseAdguardDomain(String value) {
        value = value.substring(2);
        int separator = value.indexOf('^'), modifier = value.indexOf('$'), end = value.length();
        if (separator >= 0) end = separator;
        if (modifier >= 0) end = Math.min(end, modifier);
        value = value.substring(0, end);
        int slash = value.indexOf('/');
        if (slash >= 0) value = value.substring(0, slash);
        return value.trim();
    }

    private static String parseHostsLine(String value) {
        String[] parts = value.split("\\s+");
        if (parts.length < 2 || !HostNormalizer.isIpLiteralFast(parts[0])) return value;
        return parts[1].trim();
    }

    private static boolean isValidDomainCandidate(String value) {
        if (value == null || value.isEmpty() || value.length() > 253
                || value.contains("://") || value.contains("@") || value.contains("?")
                || value.contains("=") || value.contains("%") || value.contains("*")
                || value.startsWith(".") || value.endsWith(".")
                || value.startsWith("-") || value.endsWith("-")) return false;
        String[] labels = value.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) return false;
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!(Character.isLetterOrDigit(c) || c == '-' || c == '_')) return false;
            }
        }
        return true;
    }

    @Override
    public String toString() { return "AdguardBlacklistSource{url='" + url + "'}"; }

    private static final class LimitedInputStream extends FilterInputStream {
        private final long maxBytes;
        private long totalBytes;
        private LimitedInputStream(InputStream input, long maxBytes) { super(input); this.maxBytes = maxBytes; }
        @Override
        public int read() throws IOException {
            if (totalBytes >= maxBytes) throw new IOException(LocaleUtil.getString("adguard_response_exceeds_max"));
            int value = super.read();
            if (value >= 0) totalBytes++;
            return value;
        }
        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (length == 0) return 0;
            long remaining = maxBytes - totalBytes;
            if (remaining <= 0) throw new IOException(LocaleUtil.getString("adguard_response_exceeds_max"));
            int toRead = (int) Math.min(length, remaining);
            int read = super.read(buffer, offset, toRead);
            if (read > 0) totalBytes += read;
            return read;
        }
    }
}