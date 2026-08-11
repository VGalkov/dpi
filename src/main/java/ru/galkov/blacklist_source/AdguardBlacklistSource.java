package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class AdguardBlacklistSource implements BlacklistSource {
    private static final Logger logger = LoggerFactory.getLogger(AdguardBlacklistSource.class);
    private final String url;
    private final int connectTimeout;
    private final int readTimeout;

    public AdguardBlacklistSource(
            String url,
            int connectTimeout,
            int readTimeout) {

        this.url = url;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    @Override
    public List<String> loadRules()
            throws IOException {

        logger.info("Начинается загрузка AdGuard blacklist: {}", url);

        HttpURLConnection connection =
                (HttpURLConnection)
                        new URL(url).openConnection();

        connection.setRequestMethod("GET");
        connection.setConnectTimeout(
                connectTimeout
        );
        connection.setReadTimeout(
                readTimeout
        );
        connection.setRequestProperty(
                "User-Agent",
                "Galkov-DnsProxy/1.0"
        );

        int status =
                connection.getResponseCode();

        logger.info(
                "Ответ AdGuard: HTTP {}",
                status
        );

        if (status != HttpURLConnection.HTTP_OK) {
            throw new IOException(
                    "AdGuard вернул HTTP-код " + status
            );
        }

        List<String> rules =
                new ArrayList<String>();

        try (
                InputStream input =
                        connection.getInputStream();

                BufferedReader reader =
                        new BufferedReader(
                                new InputStreamReader(
                                        input,
                                        StandardCharsets.UTF_8
                                )
                        )
        ) {
            String line;

            while ((line = reader.readLine()) != null) {
                String value =
                        normalizeLine(line);

                if (value != null) {
                    rules.add(value);
                }
            }

        } finally {
            connection.disconnect();
        }

        logger.info(
                "AdGuard blacklist загружен: правил {}",
                rules.size()
        );

        return rules;
    }

    private String normalizeLine(
            String line) {

        if (line == null) {
            return null;
        }

        String value =
                line.trim();

        if (value.isEmpty() ||
                value.startsWith("#") ||
                value.startsWith("!")) {
            return null;
        }

        /*
         * Поддержка строк формата hosts:
         *
         * 0.0.0.0 example.com
         * 127.0.0.1 example.com
         */
        String[] parts =
                value.split("\\s+");

        if (parts.length >= 2 &&
                looksLikeIp(parts[0])) {

            value = parts[1];
        }

        /*
         * Поддержка простых AdGuard-правил:
         *
         * ||example.com^
         */
        if (value.startsWith("||")) {
            value =
                    value.substring(2);

            int separator =
                    value.indexOf('^');

            if (separator >= 0) {
                value =
                        value.substring(0, separator);
            }
        }

        /*
         * Если в источнике встретятся URL-маркеры,
         * оставляем только имя домена.
         */
        int slash =
                value.indexOf('/');

        if (slash >= 0) {
            value =
                    value.substring(0, slash);
        }

        value =
                value.trim();

        return value.isEmpty()
                ? null
                : value;
    }

    private boolean looksLikeIp(
            String value) {

        return value.indexOf('.') >= 0 ||
                value.indexOf(':') >= 0;
    }

    @Override
    public String toString() {
        return "AdguardBlacklistSource{" +
                "url='" + url + '\'' +
                '}';
    }
}