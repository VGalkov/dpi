package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

public class BlacklistLoader {
    private static final Logger logger = LoggerFactory.getLogger(BlacklistLoader.class);

    private final Set<String> domains = new HashSet<>();
    private final Set<String> ips = new HashSet<>();
    private boolean loaded = false;

    private synchronized void load() {
        if (loaded) return;

        InputStream inputStream = null;
        boolean found = false;

        URL resource = getClass().getClassLoader().getResource("blacklist.txt");
        if (resource != null) {
            try {
                inputStream = resource.openStream();
                found = true;
                logger.info("Blacklist найден в Classpath: {}", resource.toExternalForm());
            } catch (IOException e) {
                logger.error("Ошибка открытия ресурса blacklist.txt", e);
            }
        } else {
            File file = new File("blacklist.txt");
            if (file.exists() && file.isFile()) {
                try {
                    inputStream = new FileInputStream(file);
                    found = true;
                    logger.info("Blacklist найден в рабочей директории: {}", file.getAbsolutePath());
                } catch (FileNotFoundException e) {
                    logger.warn("Файл blacklist.txt не найден.{}", e.getMessage());
                }
            } else {
                logger.warn("Файл blacklist.txt не найден. Фильтрация отключена.");
                loaded = true;
                return;
            }
        }

        if (found && inputStream != null) {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;

                    String cleanLine = line;
                    if (cleanLine.endsWith(".")) {
                        cleanLine = cleanLine.substring(0, cleanLine.length() - 1);
                    }

                    if (cleanLine.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                        ips.add(cleanLine.toLowerCase());
                    } else {
                        domains.add(cleanLine.toLowerCase());
                    }
                }
                logger.info("Blacklist успешно загружен. Доменов: {}, IP: {}", domains.size(), ips.size());
                loaded = true;
            } catch (IOException e) {
                logger.error("Критическая ошибка чтения blacklist.txt", e);
                loaded = true;
            } finally {
                try {
                    inputStream.close();
                } catch (IOException ignore) {}
            }
        } else {
            loaded = true;
        }
    }

    public boolean isBlocked(String host, String clientIp) {
        return isBlockedIp(clientIp) ||
                isBlockedDomain(host);
    }

    public boolean isBlockedDomain(String domain) {
        load();

        String normalized = HostNormalizer.normalizeHost(domain);

        if (normalized == null) {
            return false;
        }

        String current = normalized;

        while (true) {
            if (domains.contains(current)) {
                return true;
            }

            int dot = current.indexOf('.');

            if (dot < 0) {
                return false;
            }

            current = current.substring(dot + 1);
        }
    }

    public boolean isBlockedIp(String ip) {
        load();

        String normalized = HostNormalizer.normalizeIp(ip);

        return normalized != null &&
                ips.contains(normalized);
    }
}