package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.BlacklistRule;
import ru.galkov.util.LocaleUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static ru.galkov.Main.getConfig;

/**
 * Загрузчик выгрузки из публичного реестра РKN (без ЭЦП).
 * Парсит HTML-страницу: https://reestr.rkn.gov.ru/treatment/201/
 *
 * Сохраняет данные в кэш-файл для последующего использования RknBlacklistSource.
 *
 * @author s0506777@yandex.ru Galkov V.A.
 */
public final class RknPublicRegistrySource extends AbstractBlacklistSource {
    private static final Logger logger = LoggerFactory.getLogger(RknPublicRegistrySource.class);

    // URL публичного реестра
    private static final String REGISTRY_URL = "https://reestr.rkn.gov.ru/treatment/201/";

    // Настройки из конфигурации
    private final String cacheFilePath;
    private final Path cacheFile;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int maxPagesToParse;
    private final boolean enabled;

    // Regex для парсинга HTML таблицы РKN
    private static final Pattern TABLE_ROW_PATTERN = Pattern.compile(
            "<tr[^>]*>.*?</tr>",
            Pattern.DOTALL | Pattern.CASE_INSENSITIVE
    );

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "<td[^>]*>([^<]*\\.[^<]*)</td>",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern IP_PATTERN = Pattern.compile(
            "<td[^>]*(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}[^<]*)</td>",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern REASON_PATTERN = Pattern.compile(
            "title=\"([^\"]*)\"",
            Pattern.CASE_INSENSITIVE
    );

    public RknPublicRegistrySource() {
        // Чтение конфигурации
        String enabledStr = getConfig().get("blacklist.rkn.public.enabled");
        this.enabled = enabledStr != null && Boolean.parseBoolean(enabledStr);

        String cacheFilePathStr = getConfig().get("blacklist.rkn.public.cache-file");
        this.cacheFilePath = cacheFilePathStr != null ? cacheFilePathStr : "rkn-public-registry.xml";
        this.cacheFile = Paths.get(cacheFilePath);

        String connectTimeoutStr = getConfig().get("blacklist.rkn.public.connect-timeout");
        this.connectTimeoutMs = parsePositiveInt(connectTimeoutStr, 30000);

        String readTimeoutStr = getConfig().get("blacklist.rkn.public.read-timeout");
        this.readTimeoutMs = parsePositiveInt(readTimeoutStr, 60000);

        String maxPagesStr = getConfig().get("blacklist.rkn.public.max-pages");
        this.maxPagesToParse = parsePositiveInt(maxPagesStr, 1);

        logger.info("RknPublicRegistrySource initialized: enabled={}, cacheFile={}",
                enabled, cacheFile.toAbsolutePath());
    }

    @Override
    public List<BlacklistRule> loadRules() throws IOException {
        if (!enabled) {
            logger.info(LocaleUtil.getString("rkn_public_disabled"));
            return new ArrayList<>(0);
        }

        logger.info(LocaleUtil.getString("rkn_public_load_start"), REGISTRY_URL);

        try {
            // Шаг 1: Скачивание HTML страницы
            logger.debug(LocaleUtil.getString("rkn_public_step1_download"));
            String htmlContent = downloadHtmlPage();

            // Шаг 2: Парсинг HTML и извлечение доменов/IP
            logger.debug(LocaleUtil.getString("rkn_public_step2_parse"));
            List<BlacklistRule> rules = parseHtmlContent(htmlContent);

            // Шаг 3: Сохранение в кэш-файл (XML формат для совместимости)
            logger.debug(LocaleUtil.getString("rkn_public_step3_save_cache"));
            saveToCacheFile(rules);

            logger.info(LocaleUtil.getString("rkn_public_load_complete"), rules.size(), cacheFile.toAbsolutePath());
            return rules;

        } catch (IOException e) {
            logger.error(LocaleUtil.getString("rkn_public_download_error"), e.getMessage(), e);
            // При ошибке пробуем загрузить из кэша
            return loadFromCacheFile();
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("rkn_public_unexpected_error"), e.getMessage(), e);
            return loadFromCacheFile();
        }
    }

    /**
     * Скачивание HTML страницы реестра
     */
    private String downloadHtmlPage() throws IOException {
        logger.info("Скачивание страницы: {}", REGISTRY_URL);

        URL url = new URL(REGISTRY_URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        try {
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(connectTimeoutMs);
            conn.setReadTimeout(readTimeoutMs);
            conn.addRequestProperty("User-Agent", "DPI-RKN-Public-Loader/1.0");
            conn.addRequestProperty("Accept", "text/html,application/xhtml+xml");
            conn.addRequestProperty("Accept-Language", "ru-RU,ru;q=0.9");

            int responseCode = conn.getResponseCode();
            logger.debug("HTTP response code: {}", responseCode);

            if (responseCode >= 400) {
                throw new IOException(LocaleUtil.getString("rkn_public_http_error",
                        responseCode, conn.getResponseMessage()));
            }

            StringBuilder response = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line).append("\n");
                }
            }

            String content = response.toString();
            logger.debug("HTML content size: {} bytes", content.length());
            logger.trace("HTML preview:\n{}", content.substring(0, Math.min(1000, content.length())));

            return content;

        } finally {
            conn.disconnect();
        }
    }

    /**
     * Парсинг HTML и извлечение доменов/IP
     */
    private List<BlacklistRule> parseHtmlContent(String html) {
        List<BlacklistRule> rules = new ArrayList<>(5000);
        int domainCount = 0;
        int ipCount = 0;

        Matcher rowMatcher = TABLE_ROW_PATTERN.matcher(html);
        while (rowMatcher.find()) {
            String row = rowMatcher.group();

            // Пропускаем заголовок таблицы
            if (row.contains("<th")) {
                continue;
            }

            // Извлекаем домен
            Matcher domainMatcher = DOMAIN_PATTERN.matcher(row);
            if (domainMatcher.find()) {
                String domain = domainMatcher.group(1).trim();
                if (isValidDomain(domain)) {
                    String blockType = extractBlockType(row);
                    rules.add(new BlacklistRule(
                            BlacklistRule.RuleType.DOMAIN,
                            domain.toLowerCase(),
                            "RKN_PUBLIC",
                            null,
                            blockType
                    ));
                    domainCount++;
                }
            }

            // Извлекаем IP
            Matcher ipMatcher = IP_PATTERN.matcher(row);
            if (ipMatcher.find()) {
                String ip = ipMatcher.group(1).trim();
                if (isValidIp(ip)) {
                    String blockType = extractBlockType(row);
                    rules.add(new BlacklistRule(
                            BlacklistRule.RuleType.IP,
                            ip,
                            "RKN_PUBLIC",
                            null,
                            blockType
                    ));
                    ipCount++;
                }
            }
        }

        logger.info("Спарсено правил: {} (домены={}, IP={})", rules.size(), domainCount, ipCount);
        return rules;
    }

    /**
     * Извлечение причины блокировки из title
     */
    private String extractBlockType(String row) {
        Matcher reasonMatcher = REASON_PATTERN.matcher(row);
        if (reasonMatcher.find()) {
            return reasonMatcher.group(1).trim();
        }
        return "РKN Public Registry";
    }

    /**
     * Сохранение в кэш-файл (XML формат для совместимости с RknBlacklistSource)
     */
    private void saveToCacheFile(List<BlacklistRule> rules) throws IOException {
        String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<registry>\n");
        xml.append("  <generated>").append(timestamp).append("</generated>\n");
        xml.append("  <source>").append(REGISTRY_URL).append("</source>\n");
        xml.append("  <entries>\n");

        for (BlacklistRule rule : rules) {
            xml.append("    <entry>\n");
            xml.append("      <type>").append(rule.type()).append("</type>\n");
            xml.append("      <value>").append(escapeXml(rule.value())).append("</value>\n");
            xml.append("      <source>").append(escapeXml(rule.source())).append("</source>\n");
            // ИСПРАВЛЕНО: используем blockType() вместо reason()
            if (rule.blockType() != null) {
                xml.append("      <blockType>").append(escapeXml(rule.blockType())).append("</blockType>\n");
            }
            xml.append("    </entry>\n");
        }

        xml.append("  </entries>\n");
        xml.append("</registry>\n");

        Files.writeString(cacheFile, xml.toString(), StandardCharsets.UTF_8);
        logger.debug("Кэш сохранён: {} ({} байт)", cacheFile.toAbsolutePath(), xml.length());
    }

    /**
     * Загрузка из кэш-файла при ошибке скачивания
     */
    private List<BlacklistRule> loadFromCacheFile() throws IOException {
        if (!Files.isRegularFile(cacheFile)) {
            logger.warn(LocaleUtil.getString("rkn_public_cache_not_found"), cacheFile.toAbsolutePath());
            return new ArrayList<>(0);
        }

        logger.info(LocaleUtil.getString("rkn_public_load_from_cache"), cacheFile.toAbsolutePath());

        List<BlacklistRule> rules = new ArrayList<>(5000);
        String content = Files.readString(cacheFile, StandardCharsets.UTF_8);

        // Простой парсинг XML кэша
        Pattern valuePattern = Pattern.compile("<value>([^<]+)</value>");
        Pattern typePattern = Pattern.compile("<type>([^<]+)</type>");
        Pattern blockTypePattern = Pattern.compile("<blockType>([^<]+)</blockType>");

        String[] entries = content.split("<entry>");
        for (int i = 1; i < entries.length; i++) {
            String entry = entries[i];

            Matcher valueMatcher = valuePattern.matcher(entry);
            Matcher typeMatcher = typePattern.matcher(entry);
            Matcher blockTypeMatcher = blockTypePattern.matcher(entry);

            if (valueMatcher.find() && typeMatcher.find()) {
                String value = valueMatcher.group(1).trim();
                String type = typeMatcher.group(1).trim();
                String blockType = blockTypeMatcher.find() ? blockTypeMatcher.group(1).trim() : "РKN Public Registry";

                BlacklistRule.RuleType ruleType = "DOMAIN".equals(type)
                        ? BlacklistRule.RuleType.DOMAIN
                        : BlacklistRule.RuleType.IP;

                rules.add(new BlacklistRule(ruleType, value, "RKN_PUBLIC_CACHE", null, blockType));
            }
        }

        logger.info(LocaleUtil.getString("rkn_public_cache_loaded"), rules.size());
        return rules;
    }

    /**
     * Валидация домена
     */
    private boolean isValidDomain(String domain) {
        if (domain == null || domain.isBlank()) return false;
        domain = domain.trim();
        // Минимальная проверка: есть точка, нет пробелов
        return domain.contains(".") && !domain.contains(" ") && domain.length() >= 3;
    }

    /**
     * Валидация IP
     */
    private boolean isValidIp(String ip) {
        if (ip == null || ip.isBlank()) return false;
        ip = ip.trim();
        // Проверка формата IPv4
        return ip.matches("^\\d{1,3}(\\.\\d{1,3}){3}$");
    }

    /**
     * Экранирование XML
     */
    private String escapeXml(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder(input.length());
        for (char c : input.toCharArray()) {
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&apos;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Парсинг положительного int
     */
    private int parsePositiveInt(String value, int defaultValue) {
        if (value == null || value.isBlank()) return defaultValue;
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed > 0 ? parsed : defaultValue;
        } catch (NumberFormatException e) {
            logger.warn("Invalid int value '{}', using default {}", value, defaultValue);
            return defaultValue;
        }
    }

    @Override
    public String toString() {
        return "RknPublicRegistrySource{url=" + REGISTRY_URL + ", cacheFile=" + cacheFile + "}";
    }
}