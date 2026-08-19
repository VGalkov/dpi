    package ru.galkov.blacklist_source;

    import ru.galkov.util.BlacklistRule;
    import ru.galkov.util.LocaleUtil;

    import java.io.IOException;
    import java.net.HttpURLConnection;
    import java.net.URL;
    import java.util.List;
    /**
     * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
     */
    public final class AdguardBlacklistSource extends AbstractBlacklistSource {
        private final String url;
        private final int connectTimeout, readTimeout;

        public AdguardBlacklistSource(String url, int connectTimeout, int readTimeout) {
            this.url = url;
            this.connectTimeout = connectTimeout;
            this.readTimeout = readTimeout;
        }

        @Override
        public List<BlacklistRule> loadRules() throws IOException {
            logger.info(LocaleUtil.getString("adguard_load_started"), url);
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);
            conn.setRequestProperty("User-Agent", "Galkov-DnsProxy/1.0");

            int status = conn.getResponseCode();
            logger.info(LocaleUtil.getString("adguard_http_response"), status);
            if (status != HttpURLConnection.HTTP_OK)
                throw new IOException(LocaleUtil.getString("adguard_http_error") + status);

            List<BlacklistRule> rules = loadFromStream(conn.getInputStream(), "AdGuard");
            conn.disconnect();
            logger.info(LocaleUtil.getString("adguard_blacklist_loaded"), rules.size());
            return rules;
        }

        @Override
        protected BlacklistRule parseLine(String line, String sourceName) {
            String value = line.trim();
            if (value.isEmpty() || value.startsWith("#") || value.startsWith("!")) return null;
            String[] parts = value.split("\\s+");
            if (parts.length >= 2 && looksLikeIp(parts[0])) value = parts[1];
            if (value.startsWith("||")) {
                value = value.substring(2);
                int sep = value.indexOf('^');
                if (sep >= 0) value = value.substring(0, sep);
            }
            int slash = value.indexOf('/');
            if (slash >= 0) value = value.substring(0, slash);
            value = value.trim();
            return value.isEmpty() ? null : new BlacklistRule(BlacklistRule.RuleType.DOMAIN, value, sourceName, null, null);
        }

        private boolean looksLikeIp(String v) { return v.indexOf('.') >= 0 || v.indexOf(':') >= 0; }

        @Override
        public String toString() { return "AdguardBlacklistSource{url='" + url + "'}"; }
    }