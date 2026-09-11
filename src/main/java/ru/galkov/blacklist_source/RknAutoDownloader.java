package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static ru.galkov.Main.getConfig;

/**
 * Автоматическая загрузка выгрузки реестра запрещённых сайтов из Роскомнадзора.
 * Реализует протокол из документа:
 * https://vigruzki.rkn.gov.ru/docs/description_for_operators_actual.pdf
 *
 * Загрузка происходит в отдельный файл (не в dump.xml), который затем может быть
 * использован RknBlacklistSource.
 *
 * @author s0506777@yandex.ru Galkov V.A.
 */
public final class RknAutoDownloader {
    private static final Logger logger = LoggerFactory.getLogger(RknAutoDownloader.class);

    // URL сервиса РKN
    private static final String SERVICE_URL = "https://vigruzki.rkn.gov.ru/services/OperatorRequest/";
    private static final String TEST_SERVICE_URL = "https://vigruzki.rkn.gov.ru/services/OperatorRequestTest/";

    // Пути из конфигурации
    private final Path outputDir;
    private final String outputFileName;
    private final boolean testMode;

    // Данные оператора из конфигурации (согласно спецификации РKN)
    private final String operatorName;
    private final String inn;
    private final String ogrn;
    private final String email;

    // Файл электронной подписи запроса
    private final byte[] signatureFileBytes;

    // Таймауты и интервалы
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int pollIntervalSeconds;
    private final int maxPollAttempts;

    public RknAutoDownloader() {
        logger.info(LocaleUtil.getString("rkn_downloader_init_start"));

        // Чтение конфигурации (без значений по умолчанию)
        String testModeStr = getConfig().get("blacklist.rkn.remote.test-mode");
        this.testMode = testModeStr != null && Boolean.parseBoolean(testModeStr);
        logger.debug("testMode={}", this.testMode);

        String outputDirStr = getConfig().get("blacklist.rkn.remote.output-dir");
        this.outputDir = Paths.get(outputDirStr != null ? outputDirStr : ".");
        logger.debug("outputDir={}", this.outputDir.toAbsolutePath());

        String outputFileNameStr = getConfig().get("blacklist.rkn.remote.output-file");
        this.outputFileName = outputFileNameStr != null ? outputFileNameStr : "dump-rkn-remote.xml";
        logger.debug("outputFileName={}", this.outputFileName);

        // Данные оператора (обязательные поля согласно спецификации)
        this.operatorName = getConfig().get("blacklist.rkn.remote.operator-name");
        this.inn = getConfig().get("blacklist.rkn.remote.inn");
        this.ogrn = getConfig().get("blacklist.rkn.remote.ogrn");
        this.email = getConfig().get("blacklist.rkn.remote.email");
        logger.debug("operatorName={}, inn={}, ogrn={}, email={}",
                maskSensitive(operatorName), maskSensitive(inn), maskSensitive(ogrn), maskSensitive(email));

        // Файл электронной подписи (не emchd!)
        String signatureFilePath = getConfig().get("blacklist.rkn.remote.signature-file");
        this.signatureFileBytes = readFileIfExists(signatureFilePath);

        // Таймауты (с ручной обработкой null)
        String connectTimeoutStr = getConfig().get("blacklist.rkn.remote.connect-timeout");
        this.connectTimeoutMs = parsePositiveInt(connectTimeoutStr, 30000);
        logger.debug("connectTimeoutMs={}", this.connectTimeoutMs);

        String readTimeoutStr = getConfig().get("blacklist.rkn.remote.read-timeout");
        this.readTimeoutMs = parsePositiveInt(readTimeoutStr, 60000);
        logger.debug("readTimeoutMs={}", this.readTimeoutMs);

        String pollIntervalStr = getConfig().get("blacklist.rkn.remote.poll-interval");
        this.pollIntervalSeconds = parsePositiveInt(pollIntervalStr, 60);
        logger.debug("pollIntervalSeconds={}", this.pollIntervalSeconds);

        String maxPollAttemptsStr = getConfig().get("blacklist.rkn.remote.max-poll-attempts");
        this.maxPollAttempts = parsePositiveInt(maxPollAttemptsStr, 15);
        logger.debug("maxPollAttempts={}", this.maxPollAttempts);

        // Валидация обязательных полей
        validateConfig();

        // Создание директории вывода
        try {
            Files.createDirectories(outputDir);
            logger.info(LocaleUtil.getString("rkn_downloader_output_dir_created"), outputDir.toAbsolutePath());
        } catch (IOException e) {
            logger.error(LocaleUtil.getString("rkn_downloader_output_dir_create_error"),
                    outputDir.toAbsolutePath(), e.getMessage(), e);
            throw new RuntimeException(e);
        }

        logger.info(LocaleUtil.getString("rkn_downloader_init_complete"),
                testMode ? TEST_SERVICE_URL : SERVICE_URL);
    }

    /**
     * Маскировка чувствительных данных для логирования
     */
    private String maskSensitive(String value) {
        if (value == null || value.length() < 4) return "***";
        return value.substring(0, 2) + "***" + value.substring(value.length() - 2);
    }

    /**
     * Валидация обязательных полей конфигурации
     */
    private void validateConfig() {
        logger.debug(LocaleUtil.getString("rkn_downloader_validating_config"));

        if (operatorName == null || operatorName.isBlank()) {
            logger.error(LocaleUtil.getString("rkn_downloader_config_error"), "blacklist.rkn.remote.operator-name");
            throw new IllegalArgumentException(LocaleUtil.getString("rkn_downloader_config_error", "blacklist.rkn.remote.operator-name"));
        }
        if (inn == null || inn.isBlank()) {
            logger.error(LocaleUtil.getString("rkn_downloader_config_error"), "blacklist.rkn.remote.inn");
            throw new IllegalArgumentException(LocaleUtil.getString("rkn_downloader_config_error", "blacklist.rkn.remote.inn"));
        }
        if (ogrn == null || ogrn.isBlank()) {
            logger.error(LocaleUtil.getString("rkn_downloader_config_error"), "blacklist.rkn.remote.ogrn");
            throw new IllegalArgumentException(LocaleUtil.getString("rkn_downloader_config_error", "blacklist.rkn.remote.ogrn"));
        }
        if (email == null || email.isBlank()) {
            logger.error(LocaleUtil.getString("rkn_downloader_config_error"), "blacklist.rkn.remote.email");
            throw new IllegalArgumentException(LocaleUtil.getString("rkn_downloader_config_error", "blacklist.rkn.remote.email"));
        }

        logger.debug(LocaleUtil.getString("rkn_downloader_config_validated"));
    }

    /**
     * Выполняет загрузку выгрузки из РKN.
     * @return Путь к загруженному файлу или null при ошибке.
     */
    public Path download() {
        logger.info(LocaleUtil.getString("rkn_downloader_download_start"),
                testMode ? "TEST" : "PROD", maskSensitive(operatorName), maskSensitive(inn));

        try {
            // Шаг 1: Получение даты последней выгрузки
            logger.debug(LocaleUtil.getString("rkn_downloader_step1_get_dump_date"));
            LastDumpInfo dumpInfo = callGetLastDumpDateEx();
            if (dumpInfo.lastDumpDateUrgently == 0) {
                logger.warn(LocaleUtil.getString("rkn_downloader_dump_date_not_received"));
                return null;
            }

            ZonedDateTime dumpDate = ZonedDateTime.ofInstant(
                    java.time.Instant.ofEpochMilli(dumpInfo.lastDumpDateUrgently),
                    java.time.ZoneId.systemDefault());
            logger.info(LocaleUtil.getString("rkn_downloader_dump_date_received"),
                    dumpDate, dumpInfo.dumpFormatVersion);

            // Шаг 2: Генерация XML запроса согласно спецификации
            logger.debug(LocaleUtil.getString("rkn_downloader_step2_generate_request"));
            String requestXml = generateRequestXml();
            byte[] requestBytes = requestXml.getBytes(StandardCharsets.UTF_8);
            logger.debug("XML request generated, size={} bytes", requestBytes.length);

            // Шаг 3: Отправка запроса на выгрузку (sendRequest)
            logger.debug(LocaleUtil.getString("rkn_downloader_step3_send_request"));
            SendRequestResult sendResult = callSendRequest(requestBytes, dumpInfo.dumpFormatVersion);
            if (!sendResult.isResult) {
                logger.error(LocaleUtil.getString("rkn_downloader_send_request_failed"),
                        sendResult.resultCode, sendResult.resultComment);
                return null;
            }

            logger.info(LocaleUtil.getString("rkn_downloader_request_sent"), sendResult.code);

            // Шаг 4: Ожидание готовности результата (polling)
            logger.debug(LocaleUtil.getString("rkn_downloader_step4_poll_result"), maxPollAttempts, pollIntervalSeconds);
            GetResultResult getResult = pollResult(sendResult.code);
            if (!getResult.isResult || getResult.resultCode != 1) {
                logger.error(LocaleUtil.getString("rkn_downloader_get_result_failed"),
                        getResult.resultCode, getResult.resultComment);
                return null;
            }

            logger.info(LocaleUtil.getString("rkn_downloader_result_ready"));

            // Шаг 5: Обработка ZIP-архива и сохранение XML
            logger.debug(LocaleUtil.getString("rkn_downloader_step5_process_zip"));
            Path outputPath = processZipArchive(getResult.registerZipArchive);
            if (outputPath != null) {
                logger.info(LocaleUtil.getString("rkn_downloader_download_complete"), outputPath.toAbsolutePath());
            }
            return outputPath;

        } catch (IOException e) {
            logger.error(LocaleUtil.getString("rkn_downloader_network_error"), e.getMessage(), e);
            return null;
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("rkn_downloader_unexpected_error"), e.getMessage(), e);
            return null;
        }
    }

    /**
     * Генерация XML запроса согласно спецификации РKN
     * Формат: https://vigruzki.rkn.gov.ru/docs/description_for_operators_actual.pdf
     */
    private String generateRequestXml() {
        String requestTime = ZonedDateTime.now()
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<request>\n" +
                "  <requestTime>" + escapeXml(requestTime) + "</requestTime>\n" +
                "  <operatorName>" + escapeXml(operatorName) + "</operatorName>\n" +
                "  <inn>" + escapeXml(inn) + "</inn>\n" +
                "  <ogrn>" + escapeXml(ogrn) + "</ogrn>\n" +
                "  <email>" + escapeXml(email) + "</email>\n" +
                "</request>";

        logger.trace("Generated XML request:\n{}", xml);
        return xml;
    }

    /**
     * Шаг 1: Вызов getLastDumpDateEx
     */
    private LastDumpInfo callGetLastDumpDateEx() throws Exception {
        int maxRetries = 3;
        int retryDelayMs = 5000;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                logger.trace("Calling getLastDumpDateEx (attempt {}/{})", attempt, maxRetries);
                String soapBody = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                        "xmlns:tns=\"http://rsoc.ru\">" +
                        "<soap:Body><tns:getLastDumpDateEx/></soap:Body></soap:Envelope>";
                LastDumpInfo info = parseLastDumpDateExResponse(sendSoapRequest(soapBody));
                logger.debug("getLastDumpDateEx response: lastDumpDate={}, dumpFormatVersion={}",
                        info.lastDumpDateUrgently, info.dumpFormatVersion);
                return info;
            } catch (IOException e) {
                if (attempt == maxRetries) {
                    logger.error(LocaleUtil.getString("rkn_downloader_get_dump_date_failed"),
                            maxRetries, e.getMessage(), e);
                    throw e;
                }
                logger.warn(LocaleUtil.getString("rkn_downloader_retry_attempt"),
                        attempt, maxRetries, retryDelayMs, e.getMessage());
                Thread.sleep(retryDelayMs);
            }
        }
        throw new IllegalStateException(LocaleUtil.getString("rkn_downloader_max_retries_exceeded", maxRetries));
    }

    /**
     * Шаг 2: Вызов sendRequest с XML запросом и подписью
     */
    private SendRequestResult callSendRequest(byte[] requestBytes, String dumpFormatVersion) throws Exception {
        String reqBase64 = Base64.getEncoder().encodeToString(requestBytes);
        String sigBase64 = (signatureFileBytes == null || signatureFileBytes.length == 0) ? ""
                : Base64.getEncoder().encodeToString(signatureFileBytes);

        logger.debug("requestFile base64 size={} bytes", reqBase64.length());
        logger.debug("signatureFile base64 size={} bytes", sigBase64.length());

        StringBuilder sb = new StringBuilder();
        sb.append("<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                "xmlns:tns=\"http://rsoc.ru\">");
        sb.append("<soap:Body><tns:sendRequest>");
        sb.append("<requestFile>").append(reqBase64).append("</requestFile>");
        sb.append("<signatureFile>").append(sigBase64).append("</signatureFile>");
        sb.append("<dumpFormatVersion>").append(dumpFormatVersion).append("</dumpFormatVersion>");
        sb.append("</tns:sendRequest></soap:Body></soap:Envelope>");

        logger.trace("sendRequest SOAP body:\n{}", sb.toString());

        SendRequestResult result = parseSendRequestResponse(sendSoapRequest(sb.toString()));
        logger.debug("sendRequest response: isResult={}, resultCode={}, code={}",
                result.isResult, result.resultCode, result.code);
        return result;
    }

    /**
     * Шаг 3: Polling результата через getResult
     */
    private GetResultResult pollResult(String code) throws Exception {
        for (int attempt = 0; attempt < maxPollAttempts; attempt++) {
            logger.debug("Polling result (attempt {}/{})", attempt + 1, maxPollAttempts);

            String soapBody = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                    "xmlns:tns=\"http://rsoc.ru\">" +
                    "<soap:Body><tns:getResult><code>" + escapeXml(code) + "</code></tns:getResult></soap:Body></soap:Envelope>";

            GetResultResult result = parseGetResultResponse(sendSoapRequest(soapBody));

            if (result.isResult && result.resultCode == 1) {
                logger.info(LocaleUtil.getString("rkn_downloader_result_received"), attempt + 1);
                return result;
            }
            if (result.resultCode == 0) {
                logger.info(LocaleUtil.getString("rkn_downloader_result_not_ready"),
                        attempt + 1, maxPollAttempts, pollIntervalSeconds);
                Thread.sleep(pollIntervalSeconds * 1000L);
                continue;
            }

            logger.error(LocaleUtil.getString("rkn_downloader_result_error"),
                    result.resultCode, result.resultComment);
            throw new IllegalStateException(LocaleUtil.getString("rkn_downloader_result_error",
                    result.resultCode, result.resultComment));
        }

        logger.error(LocaleUtil.getString("rkn_downloader_poll_timeout"), maxPollAttempts, pollIntervalSeconds);
        throw new IllegalStateException(LocaleUtil.getString("rkn_downloader_poll_timeout",
                maxPollAttempts, pollIntervalSeconds));
    }

    /**
     * Шаг 4: Обработка ZIP-архива и сохранение XML в файл
     */
    private Path processZipArchive(String zipBase64Data) throws IOException {
        if (zipBase64Data == null || zipBase64Data.trim().isEmpty()) {
            logger.error(LocaleUtil.getString("rkn_downloader_empty_zip"));
            throw new IOException(LocaleUtil.getString("rkn_downloader_empty_zip"));
        }

        logger.debug("ZIP archive base64 size={} bytes", zipBase64Data.length());
        byte[] zipBytes = Base64.getDecoder().decode(zipBase64Data);
        logger.debug("ZIP archive decoded size={} bytes", zipBytes.length);

        Path tempZipFile = Files.createTempFile("rkn-download-", ".zip");
        Path outputXmlFile = outputDir.resolve(outputFileName);

        try {
            Files.write(tempZipFile, zipBytes);
            logger.debug("ZIP saved to temp file: {}", tempZipFile);

            try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(tempZipFile))) {
                ZipEntry entry;
                int xmlCount = 0;
                while ((entry = zis.getNextEntry()) != null) {
                    logger.debug("ZIP entry found: {} (size={} bytes)", entry.getName(), entry.getSize());

                    if (entry.getName().toLowerCase().endsWith(".xml")) {
                        xmlCount++;
                        logger.info(LocaleUtil.getString("rkn_downloader_xml_found"), entry.getName());

                        Files.copy(zis, outputXmlFile, StandardCopyOption.REPLACE_EXISTING);
                        logger.info(LocaleUtil.getString("rkn_downloader_xml_saved"),
                                outputXmlFile.toAbsolutePath());

                        return outputXmlFile;
                    }
                    zis.closeEntry();
                }

                if (xmlCount == 0) {
                    logger.error(LocaleUtil.getString("rkn_downloader_no_xml_in_zip"));
                    throw new IOException(LocaleUtil.getString("rkn_downloader_no_xml_in_zip"));
                }
            }

        } finally {
            Files.deleteIfExists(tempZipFile);
            logger.debug("Temp ZIP file deleted: {}", tempZipFile);
        }

        return null;
    }

    /**
     * Отправка SOAP-запроса
     */
    private String sendSoapRequest(String soapXml) throws IOException {
        String serviceUrl = testMode ? TEST_SERVICE_URL : SERVICE_URL;
        logger.debug("Sending SOAP request to: {}", serviceUrl);

        URL url = new URL(serviceUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        try {
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(connectTimeoutMs);
            conn.setReadTimeout(readTimeoutMs);
            conn.addRequestProperty("Content-Type", "text/xml; charset=utf-8");
            conn.addRequestProperty("SOAPAction", "");
            conn.addRequestProperty("User-Agent", "DPI-RKN-Loader/1.0");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(soapXml.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = conn.getResponseCode();
            logger.debug("HTTP response code: {}", responseCode);

            InputStream inputStream = (conn.getErrorStream() != null) ? conn.getErrorStream() : conn.getInputStream();

            StringBuilder response = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
            }

            String respStr = response.toString();
            logger.trace("HTTP response body ({} chars): {}", respStr.length(), respStr);

            if (responseCode == 503) {
                logger.warn(LocaleUtil.getString("rkn_downloader_service_unavailable"));
                throw new IOException(LocaleUtil.getString("rkn_downloader_service_unavailable"));
            }
            if (responseCode >= 400 && !respStr.contains("<soap:Fault>")) {
                logger.error(LocaleUtil.getString("rkn_downloader_http_error"),
                        responseCode, conn.getResponseMessage());
                throw new IOException(LocaleUtil.getString("rkn_downloader_http_error",
                        responseCode, conn.getResponseMessage()));
            }

            return respStr;

        } finally {
            conn.disconnect();
        }
    }

    /**
     * Парсинг ответа getLastDumpDateEx
     */
    private LastDumpInfo parseLastDumpDateExResponse(String xml) throws Exception {
        LastDumpInfo info = new LastDumpInfo();
        info.lastDumpDateUrgently = extractLongSafe(xml, "lastDumpDateUrgently");
        info.dumpFormatVersion = extractStringSafe(xml, "dumpFormatVersion");
        logger.trace("Parsed LastDumpInfo: lastDumpDateUrgently={}, dumpFormatVersion={}",
                info.lastDumpDateUrgently, info.dumpFormatVersion);
        return info;
    }

    /**
     * Парсинг ответа sendRequest
     */
    private SendRequestResult parseSendRequestResponse(String xml) throws Exception {
        SendRequestResult res = new SendRequestResult();
        res.isResult = Boolean.parseBoolean(extractStringSafe(xml, "result"));
        res.code = extractStringSafe(xml, "code");
        res.resultCode = Integer.parseInt(extractStringSafe(xml, "resultCode"));
        res.resultComment = extractStringSafe(xml, "resultComment");
        logger.trace("Parsed SendRequestResult: isResult={}, resultCode={}, code={}, resultComment={}",
                res.isResult, res.resultCode, res.code, res.resultComment);
        return res;
    }

    /**
     * Парсинг ответа getResult
     */
    private GetResultResult parseGetResultResponse(String xml) throws Exception {
        GetResultResult res = new GetResultResult();
        res.isResult = Boolean.parseBoolean(extractStringSafe(xml, "result"));
        res.resultCode = Integer.parseInt(extractStringSafe(xml, "resultCode"));
        res.resultComment = extractStringSafe(xml, "resultComment");
        res.registerZipArchive = extractStringSafe(xml, "registerZipArchive");
        logger.trace("Parsed GetResultResult: isResult={}, resultCode={}, registerZipArchive size={}",
                res.isResult, res.resultCode, res.registerZipArchive != null ? res.registerZipArchive.length() : 0);
        return res;
    }

    /**
     * Извлечение строкового значения из XML по тегу
     */
    private String extractStringSafe(String xml, String tagName) {
        try {
            int startTag = xml.indexOf("<" + tagName + ">");
            int endTag = xml.indexOf("</" + tagName + ">");
            if (startTag >= 0 && endTag > startTag) {
                String value = xml.substring(startTag + tagName.length() + 2, endTag);
                return value != null ? value.trim() : "";
            }
        } catch (Exception e) {
            logger.trace("Error extracting XML tag '{}': {}", tagName, e.getMessage());
        }
        return "";
    }

    /**
     * Извлечение long значения из XML
     */
    private long extractLongSafe(String xml, String tagName) {
        String val = extractStringSafe(xml, tagName);
        if (val.isEmpty()) return 0L;
        try {
            return Long.parseLong(val);
        } catch (NumberFormatException e) {
            logger.trace("Error parsing long from XML tag '{}': {}", tagName, e.getMessage());
            return 0L;
        }
    }

    /**
     * Чтение файла в байты, если файл существует
     */
    private byte[] readFileIfExists(String filePath) {
        if (filePath == null || filePath.isBlank()) {
            logger.debug("File path is null or blank, returning null");
            return null;
        }
        Path path = Paths.get(filePath);
        if (!Files.isRegularFile(path)) {
            logger.warn(LocaleUtil.getString("rkn_downloader_file_not_found"), path.toAbsolutePath());
            return null;
        }
        try {
            byte[] bytes = Files.readAllBytes(path);
            logger.info(LocaleUtil.getString("rkn_downloader_file_loaded"),
                    path.toAbsolutePath(), bytes.length);
            return bytes;
        } catch (IOException e) {
            logger.error(LocaleUtil.getString("rkn_downloader_file_read_error"),
                    path.toAbsolutePath(), e.getMessage(), e);
            return null;
        }
    }

    /**
     * Экранирование XML-специальных символов
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
     * Парсит положительное int-значение из строки.
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

    // Внутренние классы для результатов
    private static class LastDumpInfo {
        long lastDumpDateUrgently;
        String dumpFormatVersion;
    }

    private static class SendRequestResult {
        boolean isResult;
        String code;
        int resultCode;
        String resultComment;
    }

    private static class GetResultResult {
        boolean isResult;
        int resultCode;
        String resultComment;
        String registerZipArchive;
    }
}