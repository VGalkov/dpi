package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public final class BlacklistLoader {
    private static final Logger logger =
            LoggerFactory.getLogger(BlacklistLoader.class);
    private final List<BlacklistSource> sources;
    private static final String FILE_NAME = "blacklist.txt";

    private final AtomicReference<BlacklistSnapshot>
            snapshot =
            new AtomicReference<BlacklistSnapshot>(
                    BlacklistSnapshot.empty()
            );

    private volatile boolean loaded;


    public BlacklistLoader(
            List<BlacklistSource> sources) {

        if (sources == null) {
            throw new IllegalArgumentException(
                    "Список источников blacklist " +
                            "не может быть null"
            );
        }

        this.sources =
                Collections.unmodifiableList(
                        new ArrayList<BlacklistSource>(
                                sources
                        )
                );
    }

    public BlacklistSnapshot snapshot() {
        ensureLoaded();
        return snapshot.get();
    }

    public boolean isBlocked(
            String host,
            String clientIp) {

        return isBlockedIp(clientIp) ||
                isBlockedDomain(host);
    }

    public boolean isBlockedIp(
            String ip) {

        BlacklistSnapshot rules =
                snapshot();

        String normalizedIp =
                HostNormalizer.normalizeIp(ip);

        return normalizedIp != null &&
                rules.ips().contains(normalizedIp);
    }

    public void load() {
        ensureLoaded();
    }

    public boolean isBlockedDomain(
            String domain) {

        BlacklistSnapshot rules =
                snapshot();

        String normalizedDomain =
                HostNormalizer.normalizeHost(domain);

        return normalizedDomain != null &&
                rules.matchesDomain(normalizedDomain);
    }


    private void ensureLoaded() {
        if (loaded) {
            return;
        }

        synchronized (this) {
            if (loaded) {
                return;
            }

            try {
                loadInternal();
            } catch (IOException e) {
                logger.error("Ошибка загрузки {}", FILE_NAME, e);

                // Fail-closed для загрузчика означает:
                // старые правила не заменяются частично загруженными.
                snapshot.set(BlacklistSnapshot.empty());
            } finally {
                loaded = true;
            }
        }
    }

    private void loadInternal() throws IOException {
        Set<String> domains = new HashSet<>();
        Set<String> ips = new HashSet<>();

        try (InputStream input = openBlacklist();
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(input, StandardCharsets.UTF_8))) {

            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;

                String value = line.trim();

                if (value.isEmpty() || value.startsWith("#")) {
                    continue;
                }

                value = removeInlineComment(value);
                value = HostNormalizer.removeTrailingDot(value);

                if (isIp(value)) {
                    String ip = HostNormalizer.normalizeIp(value);
                    if (ip != null) {
                        ips.add(ip);
                    } else {
                        logger.warn("Некорректный IP в строке {}: {}",
                                Optional.of(lineNumber), value);
                    }
                } else {
                    String domain = HostNormalizer.normalizeHost(value);
                    if (domain != null) {
                        domains.add(domain);
                    } else {
                        logger.warn("Некорректное правило в строке {}: {}",
                                Optional.of(lineNumber), value);
                    }
                }
            }
        }

        snapshot.set(new BlacklistSnapshot(
                Collections.unmodifiableSet(
                        new HashSet<String>(domains)
                ),
                Collections.unmodifiableSet(
                        new HashSet<String>(ips)
                )
        ));
        logger.info("Blacklist загружен: доменов " + domains.size() + ", IP " + ips.size());
    }

    private InputStream openBlacklist() throws IOException {
        URL resource = getClass()
                .getClassLoader()
                .getResource(FILE_NAME);

        if (resource != null) {
            logger.info("Blacklist найден в classpath: {}",
                    resource.toExternalForm());
            return resource.openStream();
        }

        File file = new File(FILE_NAME);
        if (file.isFile()) {
            logger.info("Blacklist найден на диске: {}",
                    file.getAbsolutePath());
            return new FileInputStream(file);
        }

        throw new FileNotFoundException(
                "Файл blacklist.txt не найден");
    }

    private static String removeInlineComment(String value) {
        int index = value.indexOf('#');
        return index >= 0
                ? value.substring(0, index).trim()
                : value;
    }

    private static boolean isIp(
            String value) {

        if (value == null ||
                value.isEmpty()) {
            return false;
        }

        /*
         * IPv6 содержит двоеточие.
         */
        if (value.indexOf(':') >= 0) {
            return true;
        }

        /*
         * IPv4 проверяем строго:
         * четыре числовые части от 0 до 255.
         */
        return isIpv4(value);
    }
    private static boolean isIpv4(
            String value) {

        String[] parts =
                value.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty()) {
                return false;
            }

            for (int i = 0;
                 i < part.length();
                 i++) {

                if (!Character.isDigit(
                        part.charAt(i))) {
                    return false;
                }
            }

            try {
                int number =
                        Integer.parseInt(part);

                if (number < 0 ||
                        number > 255) {
                    return false;
                }

            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

}