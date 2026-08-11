package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.blacklist_source.BlacklistSource;

import java.io.*;
import java.net.URL;
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
            } catch (Exception e) {
                logger.error("Критическая ошибка загрузки blacklist", e);
                snapshot.set(BlacklistSnapshot.empty());
            } finally {
                loaded = true;
            }
        }
    }

    private void loadInternal() {
        Set<String> newDomains =
                new HashSet<String>();

        Set<String> newIps =
                new HashSet<String>();

        int loadedSources = 0;
        int totalRules = 0;

        for (BlacklistSource source : sources) {
            try {
                logger.info(
                        "Загрузка blacklist из источника: {}",
                        source
                );

                List<String> rules =
                        source.loadRules();

                if (rules == null) {
                    logger.warn(
                            "Источник {} вернул null вместо списка правил",
                            source
                    );
                    continue;
                }

                logger.info(
                        "Источник {} вернул правил: {}",
                        source,
                        rules.size()
                );

                loadedSources++;

                for (String rawRule : rules) {
                    String rule =
                            normalizeRule(rawRule);

                    if (rule == null) {
                        continue;
                    }

                    if (isIpLiteral(rule)) {
                        String ip =
                                normalizeIp(rule);

                        if (ip != null) {
                            newIps.add(ip);
                            totalRules++;
                        } else {
                            logger.debug(
                                    "Пропущен некорректный IP: {}",
                                    rule
                            );
                        }

                    } else {
                        String domain =
                                normalizeDomain(rule);

                        if (domain != null) {
                            newDomains.add(domain);
                            totalRules++;
                        } else {
                            logger.debug(
                                    "Пропущено некорректное доменное правило: {}",
                                    rule
                            );
                        }
                    }
                }

            } catch (Exception e) {
                logger.error(
                        "Не удалось загрузить blacklist " +
                                "из источника {}",
                        source,
                        e
                );
            }
        }

        /*
         * Set.copyOf() не используется, поскольку проект
         * собирается под Java 8.
         */
        Set<String> immutableDomains =
                Collections.unmodifiableSet(
                        new HashSet<String>(newDomains)
                );

        Set<String> immutableIps =
                Collections.unmodifiableSet(
                        new HashSet<String>(newIps)
                );

        snapshot.set(
                new BlacklistSnapshot(
                        immutableDomains,
                        immutableIps
                )
        );

        logger.info(
                "Blacklist загружен: источников {}, " +
                        "правил {}, доменов {}, IP {}",
                loadedSources,
                totalRules,
                immutableDomains.size(),
                immutableIps.size()
        );
    }

    private static String normalizeRule(
            String value) {

        if (value == null) {
            return null;
        }

        String result =
                value.trim();

        if (result.isEmpty() ||
                result.startsWith("#") ||
                result.startsWith("!")) {
            return null;
        }

        int commentIndex =
                result.indexOf('#');

        if (commentIndex >= 0) {
            result =
                    result.substring(
                            0,
                            commentIndex
                    ).trim();
        }

        return result.isEmpty()
                ? null
                : result;
    }
    private static boolean isIpLiteral(
            String value) {

        if (value == null ||
                value.isEmpty()) {
            return false;
        }

        if (value.indexOf(':') >= 0) {
            return true;
        }

        return isIpv4Literal(value);
    }

    private static boolean isIpv4Literal(
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

    private static String normalizeDomain(
            String value) {

        return HostNormalizer.normalizeHost(value);
    }
    private static String normalizeIp(
            String value) {

        return HostNormalizer.normalizeIp(value);
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