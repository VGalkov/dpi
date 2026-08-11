package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.util.*;

public final class BlacklistLoader {

    private static final Logger logger =
            LoggerFactory.getLogger(BlacklistLoader.class);

    private final List<BlacklistSource> sources;

    private volatile Set<String> domains =
            Collections.emptySet();

    private volatile Set<String> ips =
            Collections.emptySet();

    public BlacklistLoader(
            List<BlacklistSource> sources) {

        this.sources = Collections.unmodifiableList(
                new ArrayList<BlacklistSource>(sources)
        );
    }

    public synchronized void load() {
        Set<String> newDomains =
                new HashSet<String>();

        Set<String> newIps =
                new HashSet<String>();

        int sourceCount = 0;
        int ruleCount = 0;

        for (BlacklistSource source : sources) {
            try {
                List<String> rules =
                        source.loadRules();

                sourceCount++;

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
                            ruleCount++;
                        }
                    } else {
                        String domain =
                                normalizeDomain(rule);

                        if (domain != null) {
                            newDomains.add(domain);
                            ruleCount++;
                        }
                    }
                }

            } catch (IOException e) {
                logger.error(
                        "Не удалось загрузить blacklist из источника {}",
                        source,
                        e
                );
            }
        }

        /*
         * Меняем ссылки только после полной обработки
         * всех источников. Часть старого списка не смешивается
         * с частично загруженным новым.
         */
        domains = Collections.unmodifiableSet(
                newDomains
        );

        ips = Collections.unmodifiableSet(
                newIps
        );

        logger.info(
                "Blacklist загружен: источников {}, правил {}, доменов {}, IP {}",
                sourceCount,
                ruleCount,
                domains.size(),
                ips.size()
        );
    }

    public boolean isBlocked(
            String host,
            String clientIp) {

        return isBlockedIp(clientIp) ||
                isBlockedDomain(host);
    }

    public boolean isBlockedDomain(
            String domain) {

        String normalized =
                normalizeDomain(domain);

        if (normalized == null) {
            return false;
        }

        String current = normalized;

        while (true) {
            if (domains.contains(current)) {
                return true;
            }

            int dot =
                    current.indexOf('.');

            if (dot < 0) {
                return false;
            }

            current =
                    current.substring(dot + 1);
        }
    }

    public boolean isBlockedIp(
            String ip) {

        String normalized =
                normalizeIp(ip);

        return normalized != null &&
                ips.contains(normalized);
    }

    private static String normalizeRule(
            String value) {

        if (value == null) {
            return null;
        }

        String result =
                value.trim();

        if (result.isEmpty() ||
                result.startsWith("#")) {
            return null;
        }

        while (result.endsWith(".")) {
            result = result.substring(
                    0,
                    result.length() - 1
            );
        }

        return result;
    }

    private static String normalizeDomain(
            String value) {

        if (value == null) {
            return null;
        }

        String domain =
                value.trim()
                        .toLowerCase(Locale.ROOT);

        while (domain.endsWith(".")) {
            domain = domain.substring(
                    0,
                    domain.length() - 1
            );
        }

        if (domain.isEmpty() ||
                domain.contains(":") ||
                domain.contains("/") ||
                domain.contains(" ")) {
            return null;
        }

        return domain;
    }

    private static String normalizeIp(
            String value) {

        if (value == null) {
            return null;
        }

        String ip =
                value.trim();

        if (!isIpLiteral(ip)) {
            return null;
        }

        try {
            return InetAddress
                    .getByName(ip)
                    .getHostAddress()
                    .toLowerCase(Locale.ROOT);

        } catch (Exception e) {
            return null;
        }
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

            for (int i = 0; i < part.length(); i++) {
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