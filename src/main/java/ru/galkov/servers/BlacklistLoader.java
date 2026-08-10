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
                } catch (FileNotFoundException e) {}
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
        load();

        if (!loaded || (domains.isEmpty() && ips.isEmpty())) return false;

        if (clientIp != null && !clientIp.isEmpty()) {
            String ipClean = clientIp;
            if (ipClean.contains("/")) ipClean = ipClean.split("/")[0];
            if (ips.contains(ipClean.toLowerCase())) {
                logger.debug("BLOCKED [IP]: Клиент {} заблокирован", clientIp);
                return true;
            }
        }

        if (host != null && !host.isEmpty()) {
            String hClean = host.toLowerCase();

            if (hClean.contains(":")) hClean = hClean.split(":")[0];

            if (hClean.endsWith(".")) hClean = hClean.substring(0, hClean.length() - 1);

            if (domains.contains(hClean)) {
                logger.info("BLOCKED [Domain]: Точное совпадение {}", hClean);
                return true;
            }

            for (String blocked : domains) {
                if (hClean.endsWith("." + blocked)) {
                    logger.info("BLOCKED [Subdomain]: {} совпадает с правилом {}", hClean, blocked);
                    return true;
                }
            }
        }
        return false;
    }
}