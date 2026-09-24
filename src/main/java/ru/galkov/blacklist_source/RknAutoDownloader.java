package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import ru.galkov.AppConfig;
import ru.galkov.Main;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static ru.galkov.Main.getConfig;

public final class RknAutoDownloader {
    private static final Logger logger = LoggerFactory.getLogger(RknAutoDownloader.class);

    private static final String SOAP_ENVELOPE_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String RKN_NAMESPACE = "http://vigruzki.rkn.gov.ru/OperatorRequest/";
    private static final String SOAP_ACTION_BASE = "http://vigruzki.rkn.gov.ru/services/OperatorRequest/";

    private static final String OP_GET_LAST_DUMP_DATE_EX = "getLastDumpDateEx";
    private static final String OP_SEND_REQUEST = "sendRequest";
    private static final String OP_GET_RESULT = "getResult";

    private static final int CONNECT_TIMEOUT_MILLIS = 30_000;
    private static final int READ_TIMEOUT_MILLIS = 300_000;
    private static final int MAX_HTTP_ERROR_BODY_FOR_EXCEPTION = 2_000;
    private static final int MAX_HTTP_BODY_FOR_DEBUG_LOG = 20_000;

    private final String serviceUrl;
    private final Path requestFilePath;
    private final Path signatureFilePath;
    private final Path outputFilePath;      // dumpByCert.xml
    private final Path dumpFilePath;        // dump.xml
    private final Path oldDumpFilePath;     // dump_old.xml
    private final String dumpFormatVersion;
    private final Duration updateInterval;
    private final Duration resultPollInterval;
    private final Duration resultTimeout;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean updateInProgress = new AtomicBoolean(false);

    private volatile ScheduledExecutorService scheduler;
    private volatile Instant lastSuccessfulUpdate;
    private volatile long lastKnownDumpDate;
    private volatile long lastKnownDumpDateUrgently;
    private volatile int consecutiveFailures;

    public RknAutoDownloader() {
        AppConfig config = getConfig();
        this.serviceUrl = config.get("blacklist.rkn.remote.service-url").trim();
        this.requestFilePath = Path.of(config.get("blacklist.rkn.remote.request-file")).toAbsolutePath().normalize();
        this.signatureFilePath = Path.of(config.get("blacklist.rkn.remote.signature-file")).toAbsolutePath().normalize();
        this.outputFilePath = Path.of(config.get("blacklist.rkn.remote.output-file")).toAbsolutePath().normalize();
        this.dumpFilePath = Path.of(config.get("blacklist.rkn.xml-file")).toAbsolutePath().normalize();
        this.oldDumpFilePath = dumpFilePath.getParent().resolve("dump_old.xml");
        this.dumpFormatVersion = config.get("blacklist.rkn.remote.dump-format-version").trim();
        this.updateInterval = Duration.ofHours(config.getInt("blacklist.rkn.remote.update-interval-hours"));
        this.resultPollInterval = Duration.ofSeconds(config.getInt("blacklist.rkn.remote.result-poll-interval-seconds"));
        this.resultTimeout = Duration.ofMinutes(config.getInt("blacklist.rkn.remote.result-timeout-minutes"));
        validateConfiguration();

        logger.info("RKN downloader initialized: endpoint={}, requestFile={}, signatureFile={}, outputFile={}, dumpFile={}",
                serviceUrl, requestFilePath.getFileName(), signatureFilePath.getFileName(), outputFilePath.getFileName(), dumpFilePath.getFileName());
        logger.debug("Full config: serviceUrl={}, dumpFormatVersion={}, updateInterval={}h, pollInterval={}s, timeout={}m",
                serviceUrl, dumpFormatVersion, updateInterval.toHours(), resultPollInterval.toSeconds(), resultTimeout.toMinutes());
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            logger.warn("RKN downloader already running");
            return;
        }

        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "RKN-AutoDownloader-Thread");
            thread.setDaemon(true);
            thread.setUncaughtExceptionHandler((t, error) -> logger.error("Unhandled exception in RKN downloader thread", error));
            return thread;
        });

        scheduler.schedule(this::checkAndUpdate, 5, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(this::checkAndUpdate, updateInterval.toSeconds(), updateInterval.toSeconds(), TimeUnit.SECONDS);
        logger.info("RKN downloader started: first check in 5s, interval={}h", updateInterval.toHours());
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) return;

        ScheduledExecutorService executor = scheduler;
        scheduler = null;

        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(10, TimeUnit.SECONDS)) executor.shutdownNow();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                executor.shutdownNow();
            }
        }

        logger.info("RKN downloader stopped: lastSuccessfulUpdate={}, failures={}",
                lastSuccessfulUpdate != null ? lastSuccessfulUpdate : "never", consecutiveFailures);
    }

    public void forceLoad() {
        logger.info("Forced RKN update requested");
        checkAndUpdate();
    }

    private void checkAndUpdate() {
        if (!running.get()) {
            logger.debug("RKN update skipped: stopped");
            return;
        }

        if (!updateInProgress.compareAndSet(false, true)) {
            logger.warn("RKN update skipped: previous update still in progress");
            return;
        }

        logger.info("=== RKN update check started ===");

        try {
            LastDumpDates dates = getLastDumpDates();
            boolean urgentChanged = lastKnownDumpDateUrgently > 0 && dates.lastDumpDateUrgently > lastKnownDumpDateUrgently;
            boolean outputFileMissing = !Files.isRegularFile(outputFilePath);
            boolean noSuccessfulDownload = lastSuccessfulUpdate == null;
            boolean scheduledRefreshRequired = noSuccessfulDownload || outputFileMissing ||
                    Duration.between(lastSuccessfulUpdate, Instant.now()).compareTo(updateInterval) >= 0;

            logger.info("RKN dates: regular={}, urgent={}, prevRegular={}, prevUrgent={}",
                    formatEpochMillis(dates.lastDumpDate), formatEpochMillis(dates.lastDumpDateUrgently),
                    formatEpochMillis(lastKnownDumpDate), formatEpochMillis(lastKnownDumpDateUrgently));

            boolean updateRequired = urgentChanged || scheduledRefreshRequired;
            if (!updateRequired) {
                lastKnownDumpDate = dates.lastDumpDate;
                lastKnownDumpDateUrgently = dates.lastDumpDateUrgently;
                logger.info("RKN update not required");
                return;
            }

            logger.info("RKN update required: {}", urgentChanged ? "urgent" : "scheduled");
            requestAndSaveDumpWithRetry();

            lastKnownDumpDate = dates.lastDumpDate;
            lastKnownDumpDateUrgently = dates.lastDumpDateUrgently;
            lastSuccessfulUpdate = Instant.now();
            consecutiveFailures = 0;

            logger.info("=== RKN update completed: {} ===", outputFilePath.toAbsolutePath());

            rotateDumpFiles();

        } catch (Exception e) {
            consecutiveFailures++;
            logger.error("RKN update failed: failures={}, error={}", consecutiveFailures, e.getMessage());
            logger.debug("Details:", e);
        } finally {
            updateInProgress.set(false);
        }
    }

    public void rotateDumpFiles() throws IOException {
        synchronized (Main.DUMP_FILE_LOCK) {
            if (!Files.isRegularFile(outputFilePath))
                throw new IOException("Cannot rotate: " + outputFilePath.getFileName() + " does not exist");

            if (Files.size(outputFilePath) == 0)
                throw new IOException("Cannot rotate: " + outputFilePath.getFileName() + " is empty");


            logger.info("Rotating dump files: {} -> {}, {} -> {}",
                    dumpFilePath.getFileName(), oldDumpFilePath.getFileName(),
                    outputFilePath.getFileName(), dumpFilePath.getFileName());

            if (Files.isRegularFile(oldDumpFilePath)) {
                Files.delete(oldDumpFilePath);
                logger.debug("Deleted old backup: {}", oldDumpFilePath.getFileName());
            }

            if (Files.isRegularFile(dumpFilePath)) {
                Files.move(dumpFilePath, oldDumpFilePath, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
                logger.info("Moved {} -> {}", dumpFilePath.getFileName(), oldDumpFilePath.getFileName());
            }

            Files.move(outputFilePath, dumpFilePath, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            logger.info("Moved {} -> {}", outputFilePath.getFileName(), dumpFilePath.getFileName());

            logger.info("Dump files rotation completed successfully");
        }
    }

    private void requestAndSaveDumpWithRetry() throws Exception {
        final int maxAttempts = 3;
        final long baseRetryDelayMillis = 60_000L;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                logger.info("--- RKN request attempt {}/{} ---", attempt, maxAttempts);
                requestAndSaveDump();
                return;
            } catch (RknBusinessException e) {
                logger.error("RKN business error: resultCode={}, message={}", e.resultCode, e.getMessage());
                throw e;
            } catch (Exception e) {
                logger.warn("RKN technical error attempt {}/{}: {}", attempt, maxAttempts, e.getMessage());
                logger.debug("Details:", e);

                if (attempt == maxAttempts) throw e;

                long retryDelayMillis = baseRetryDelayMillis * attempt;
                logger.info("Retry after {} ms", retryDelayMillis);
                Thread.sleep(retryDelayMillis);
            }
        }
    }

    private void requestAndSaveDump() throws Exception {
        logger.debug("[1/5] Validating files...");
        validateInputFile(requestFilePath, "request.xml");
        validateInputFile(signatureFilePath, "request.xml.sig");

        byte[] requestFileBytes = Files.readAllBytes(requestFilePath);
        byte[] signatureFileBytes = Files.readAllBytes(signatureFilePath);
        logger.info("[1/5] Files read: request={} bytes, signature={} bytes",
                requestFileBytes.length, signatureFileBytes.length);

        String requestFileBase64 = Base64.getEncoder().encodeToString(requestFileBytes);
        String signatureFileBase64 = Base64.getEncoder().encodeToString(signatureFileBytes);
        logger.debug("[1/5] Base64: request={} chars, signature={} chars",
                requestFileBase64.length(), signatureFileBase64.length());

        logger.debug("[2/5] Calling sendRequest...");
        SendRequestResponse sendResponse = sendRequest(requestFileBase64, signatureFileBase64);
        logger.info("[2/5] sendRequest: result={}, code={}, comment={}",
                sendResponse.result, safe(sendResponse.code), safe(sendResponse.resultComment));

        if (!sendResponse.result)
            throw new RknBusinessException(-100, "sendRequest rejected: " + safe(sendResponse.resultComment));

        if (isBlank(sendResponse.code))
            throw new IOException("sendRequest returned empty code");


        logger.info("[2/5] Request accepted: code={}", sendResponse.code);

        logger.debug("[3/5] Waiting for getResult...");
        GetResultResponse resultResponse = waitForResult(sendResponse.code);

        if (resultResponse.resultCode != 1)
            throw new RknBusinessException(resultResponse.resultCode,
                    "resultCode=" + resultResponse.resultCode + ": " + safe(resultResponse.resultComment));

        if (isBlank(resultResponse.registerZipArchiveBase64))
            throw new IOException("getResult returned empty registerZipArchive");


        logger.info("[3/5] Result ready: operator={}, inn={}",
                safe(resultResponse.operatorName), safe(resultResponse.inn));

        logger.debug("[4/5] Decoding ZIP...");
        byte[] zipBytes = Base64.getDecoder().decode(removeWhitespace(resultResponse.registerZipArchiveBase64));
        logger.info("[4/5] ZIP decoded: {} bytes", zipBytes.length);
        validateZipHeader(zipBytes);

        logger.debug("[5/5] Extracting XML...");
        extractXmlFromZip(zipBytes);
        logger.info("[5/5] XML saved: {}", outputFilePath.toAbsolutePath());
    }

    private LastDumpDates getLastDumpDates() throws Exception {
        String soapRequest = createSoapEnvelope(OP_GET_LAST_DUMP_DATE_EX, "");
        logger.debug("SOAP {} request:\n{}", OP_GET_LAST_DUMP_DATE_EX, soapRequest);
        String soapResponse = postSoap(OP_GET_LAST_DUMP_DATE_EX, soapRequest);
        logger.debug("SOAP {} response:\n{}", OP_GET_LAST_DUMP_DATE_EX, trimForLog(soapResponse, MAX_HTTP_BODY_FOR_DEBUG_LOG));

        ensureNoSoapFault(soapResponse);
        Document document = parseXml(soapResponse);
        long lastDumpDate = getRequiredLong(document, "lastDumpDate");
        long lastDumpDateUrgently = getRequiredLong(document, "lastDumpDateUrgently");
        long lastDumpDateSocResources = getOptionalLong(document, "lastDumpDateSocResources", 0L);

        logger.info("RKN {}: lastDumpDate={}, lastDumpDateUrgently={}",
                OP_GET_LAST_DUMP_DATE_EX, formatEpochMillis(lastDumpDate), formatEpochMillis(lastDumpDateUrgently));

        return new LastDumpDates(lastDumpDate, lastDumpDateUrgently, lastDumpDateSocResources);
    }

    private SendRequestResponse sendRequest(String requestFileBase64, String signatureFileBase64) throws Exception {
        String operationBody = element("requestFile", requestFileBase64)
                + element("signatureFile", signatureFileBase64)
                + element("dumpFormatVersion", dumpFormatVersion);

        String soapRequest = createSoapEnvelope(OP_SEND_REQUEST, operationBody);
        logger.debug("SOAP {} formed: length={} bytes", OP_SEND_REQUEST,
                soapRequest.getBytes(StandardCharsets.UTF_8).length);
        String soapResponse = postSoap(OP_SEND_REQUEST, soapRequest);
        logger.debug("SOAP {} response:\n{}", OP_SEND_REQUEST, trimForLog(soapResponse, MAX_HTTP_BODY_FOR_DEBUG_LOG));
        ensureNoSoapFault(soapResponse);
        Document document = parseXml(soapResponse);
        boolean result = getRequiredBoolean(document, "result");
        String resultComment = getOptionalText(document, "resultComment");
        String code = getOptionalText(document, "code");

        return new SendRequestResponse(result, resultComment, code);
    }

    private GetResultResponse waitForResult(String requestCode) throws Exception {
        Instant deadline = Instant.now().plus(resultTimeout);
        int pollNumber = 0;
        logger.info("Waiting {}s before first getResult poll", resultPollInterval.toSeconds());
        sleepForResultPollInterval();

        while (Instant.now().isBefore(deadline)) {
            pollNumber++;
            logger.info("getResult poll #{}/{}: code={}", pollNumber,
                    TimeUnit.MILLISECONDS.toMinutes(resultTimeout.toMillis()), requestCode);

            GetResultResponse response = getResult(requestCode);
            logger.info("Poll #{}: resultCode={}, comment={}",
                    pollNumber, response.resultCode, safe(response.resultComment));

            if (response.resultCode == 0) {
                logger.debug("Still processing, next poll in {}s", resultPollInterval.toSeconds());
                sleepForResultPollInterval();
                continue;
            }
            if (response.resultCode < 0)
                throw new RknBusinessException(response.resultCode, "Rejected: " + safe(response.resultComment));

            if (response.resultCode == 1) return response;

            throw new RknBusinessException(response.resultCode,
                    "Unsupported resultCode=" + response.resultCode);
        }

        throw new IOException("Timeout waiting for getResult: " + requestCode);
    }

    private GetResultResponse getResult(String requestCode) throws Exception {
        String operationBody = element("code", requestCode);
        String soapRequest = createSoapEnvelope(OP_GET_RESULT, operationBody);
        logger.debug("SOAP {} request for code={}:\n{}", OP_GET_RESULT, requestCode, soapRequest);
        String soapResponse = postSoap(OP_GET_RESULT, soapRequest);
        logger.debug("SOAP {} response:\n{}", OP_GET_RESULT, trimForLog(soapResponse, MAX_HTTP_BODY_FOR_DEBUG_LOG));

        ensureNoSoapFault(soapResponse);
        Document document = parseXml(soapResponse);

        boolean result = getRequiredBoolean(document, "result");
        String resultComment = getOptionalText(document, "resultComment");
        int resultCode = getRequiredInt(document, "resultCode");
        String registerZipArchive = getOptionalText(document, "registerZipArchive");
        String dumpFormatVersion = getOptionalText(document, "dumpFormatVersion");
        String operatorName = getOptionalText(document, "operatorName");
        String inn = getOptionalText(document, "inn");

        return new GetResultResponse(result, resultComment, resultCode,
                registerZipArchive, dumpFormatVersion, operatorName, inn);
    }

    private String postSoap(String operation, String soapBody) throws IOException {
        URL url = new URL(serviceUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        byte[] requestBytes = soapBody.getBytes(StandardCharsets.UTF_8);
        long startedAt = System.nanoTime();

        try {
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
            connection.setReadTimeout(READ_TIMEOUT_MILLIS);
            connection.setDoOutput(true);
            connection.setUseCaches(false);
            connection.setRequestProperty("Content-Type", "text/xml; charset=UTF-8");

            String soapAction = SOAP_ACTION_BASE + operation;
            connection.setRequestProperty("SOAPAction", "\"" + soapAction + "\"");

            connection.setRequestProperty("Accept", "text/xml, */*");
            connection.setRequestProperty("Connection", "close");
            connection.setRequestProperty("User-Agent", "DPI-RKN-AutoDownloader/1.0");

            logger.info("[HTTP] POST {}, endpoint={}, bytes={}", operation, serviceUrl, requestBytes.length);
            logger.debug("[HTTP] Headers: Content-Type=text/xml, SOAPAction=\"{}\"", soapAction);

            try (OutputStream output = connection.getOutputStream()) {
                output.write(requestBytes);
                output.flush();
            }

            int status = connection.getResponseCode();
            long durationMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);

            logger.info("[HTTP] Response {}, status={}, {}ms, contentType={}, length={}",
                    operation, status, durationMillis,
                    connection.getContentType(), connection.getContentLengthLong());

            InputStream responseStream = (status >= 200 && status < 300) ?
                    connection.getInputStream() : connection.getErrorStream();
            String responseText = readTextStream(responseStream);

            logger.debug("[HTTP] Response body:\n{}", trimForLog(responseText, MAX_HTTP_BODY_FOR_DEBUG_LOG));

            if (status == 503) {
                if (responseText.contains("Сервис временно недоступен") ||
                        responseText.contains("Service Unavailable")) {
                    logger.warn("[HTTP] 503: RKN сервис временно недоступен");
                    throw new IOException("RKN сервис временно недоступен (HTTP 503). " +
                            "Проверите https://vigruzki.rkn.gov.ru/services/OperatorRequest/ в браузере.");
                }
            }

            if (status != HttpURLConnection.HTTP_OK)
                throw new IOException("RKN HTTP " + status + " (" + operation + "): " +
                        trimForLog(responseText, MAX_HTTP_ERROR_BODY_FOR_EXCEPTION));

            if (isBlank(responseText))
                throw new IOException("HTTP 200 but empty response (" + operation + ")");

            return responseText;

        } finally {
            connection.disconnect();
        }
    }

    private static String createSoapEnvelope(String operation, String operationBody) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<soapenv:Envelope "
                + "xmlns:soapenv=\"" + SOAP_ENVELOPE_NAMESPACE + "\" "
                + "xmlns:ns=\"" + RKN_NAMESPACE + "\">"
                + "<soapenv:Header/>"
                + "<soapenv:Body>"
                + "<ns:" + operation + ">"
                + operationBody
                + "</ns:" + operation + ">"
                + "</soapenv:Body>"
                + "</soapenv:Envelope>";
    }

    private static String element(String name, String value) {
        return "<" + name + ">" + escapeXml(value) + "</" + name + ">";
    }

    private static String escapeXml(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    private static Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        DocumentBuilder builder = factory.newDocumentBuilder();
        try (ByteArrayInputStream input = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))) {
            return builder.parse(input);
        }
    }

    private static void ensureNoSoapFault(String soapResponse) throws IOException {
        try {
            Document document = parseXml(soapResponse);
            NodeList faults = document.getElementsByTagNameNS(SOAP_ENVELOPE_NAMESPACE, "Fault");
            if (faults.getLength() == 0) faults = document.getElementsByTagName("soapenv:Fault");
            if (faults.getLength() == 0) faults = document.getElementsByTagName("SOAP-ENV:Fault");

            if (faults.getLength() > 0) {
                String faultMessage = faults.item(0).getTextContent();
                throw new IOException("SOAP Fault: " + trimForLog(faultMessage, MAX_HTTP_ERROR_BODY_FOR_EXCEPTION));
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Could not parse SOAP response", e);
        }
    }

    private static String getRequiredText(Document document, String localName) throws IOException {
        String value = getOptionalText(document, localName);
        if (isBlank(value)) throw new IOException("Required field absent: " + localName);
        return value;
    }

    private static String getOptionalText(Document document, String localName) {
        NodeList nodes = document.getElementsByTagNameNS("*", localName);
        if (nodes.getLength() == 0) nodes = document.getElementsByTagName(localName);
        if (nodes.getLength() == 0) return null;
        String text = nodes.item(0).getTextContent();
        return text != null ? text.trim() : null;
    }

    private static boolean getRequiredBoolean(Document document, String localName) throws IOException {
        String value = getRequiredText(document, localName);
        if (!"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value))
            throw new IOException("Invalid boolean: " + localName + "=" + value);

        return Boolean.parseBoolean(value);
    }

    private static int getRequiredInt(Document document, String localName) throws IOException {
        String value = getRequiredText(document, localName);
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IOException("Invalid integer: " + localName + "=" + value, e);
        }
    }

    private static long getRequiredLong(Document document, String localName) throws IOException {
        String value = getRequiredText(document, localName);
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new IOException("Invalid long: " + localName + "=" + value, e);
        }
    }

    private static long getOptionalLong(Document document, String localName, long defaultValue) throws IOException {
        String value = getOptionalText(document, localName);
        if (isBlank(value)) return defaultValue;
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new IOException("Invalid long: " + localName + "=" + value, e);
        }
    }

    private static void validateZipHeader(byte[] bytes) throws IOException {
        if (bytes == null || bytes.length < 4)
            throw new IOException("ZIP archive is null or too short");

        boolean regularZip = (bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] == 3 && bytes[3] == 4);
        boolean emptyZip = (bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] == 5 && bytes[3] == 6);
        if (!regularZip && !emptyZip) {
            String prefix = new String(bytes, 0, Math.min(bytes.length, 500), StandardCharsets.UTF_8);
            throw new IOException("Not a ZIP file. Prefix=" + prefix);
        }
    }

    private void extractXmlFromZip(byte[] zipBytes) throws IOException {
        try (ZipInputStream zipInput = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zipInput.getNextEntry()) != null) {
                logger.debug("[ZIP] Entry: {}, size={}, compressed={}",
                        entry.getName(), entry.getSize(), entry.getCompressedSize());

                if (!entry.isDirectory() && entry.getName().toLowerCase(Locale.ROOT).endsWith(".xml")) {
                    byte[] xmlBytes = readAllBytes(zipInput);
                    if (xmlBytes.length == 0) {
                        throw new IOException("ZIP XML entry empty: " + entry.getName());
                    }

                    Path parent = outputFilePath.getParent();
                    if (parent != null) Files.createDirectories(parent);

                    Files.write(outputFilePath, xmlBytes);
                    logger.info("[ZIP] Extracted: {}, output={}, bytes={}",
                            entry.getName(), outputFilePath.toAbsolutePath(), xmlBytes.length);
                    return;
                }
                zipInput.closeEntry();
            }
        }
        throw new IOException("ZIP does not contain XML");
    }

    private void validateConfiguration() {
        if (serviceUrl.isBlank()) throw new IllegalArgumentException("serviceUrl is empty");
        if (dumpFormatVersion.isBlank()) throw new IllegalArgumentException("dumpFormatVersion is empty");
        if (updateInterval.isNegative() || updateInterval.isZero())
            throw new IllegalArgumentException("updateInterval must be > 0");

        if (resultPollInterval.isNegative() || resultPollInterval.isZero())
            throw new IllegalArgumentException("resultPollInterval must be > 0");

        if (resultTimeout.isNegative() || resultTimeout.isZero())
            throw new IllegalArgumentException("resultTimeout must be > 0");

        if (resultPollInterval.compareTo(resultTimeout) >= 0)
            throw new IllegalArgumentException("resultPollInterval must be < resultTimeout");

    }

    private static void validateInputFile(Path path, String fileName) throws IOException {
        if (!Files.isRegularFile(path))
            throw new FileNotFoundException(fileName + " not found: " + path.toAbsolutePath());

        if (Files.size(path) <= 0)
            throw new IOException(fileName + " is empty: " + path.toAbsolutePath());

    }

    private static byte[] readAllBytes(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[16 * 1024];
        int read;
        while ((read = input.read(buffer)) != -1)
            output.write(buffer, 0, read);

        return output.toByteArray();
    }

    private static String readTextStream(InputStream input) throws IOException {
        if (input == null) return "";
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null)
                result.append(line).append('\n');

            return result.toString();
        }
    }

    private void sleepForResultPollInterval() throws IOException {
        try {
            Thread.sleep(resultPollInterval.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for getResult", e);
        }
    }

    private static String removeWhitespace(String value) {
        return value == null ? "" : value.replaceAll("\\s+", "");
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String trimForLog(String value, int maxLength) {
        if (value == null) return "";
        if (value.length() <= maxLength) return value;
        return value.substring(0, maxLength) + "\n... [truncated, original=" + value.length() + "]";
    }

    private static String formatEpochMillis(long epochMillis) {
        if (epochMillis <= 0) return "not-set(" + epochMillis + ")";
        return Instant.ofEpochMilli(epochMillis) + " (" + epochMillis + ")";
    }

    private static final class LastDumpDates {
        private final long lastDumpDate;
        private final long lastDumpDateUrgently;
        private final long lastDumpDateSocResources;
        private LastDumpDates(long lastDumpDate, long lastDumpDateUrgently, long lastDumpDateSocResources) {
            this.lastDumpDate = lastDumpDate;
            this.lastDumpDateUrgently = lastDumpDateUrgently;
            this.lastDumpDateSocResources = lastDumpDateSocResources;
        }
    }

    private static final class SendRequestResponse {
        private final boolean result;
        private final String resultComment;
        private final String code;
        private SendRequestResponse(boolean result, String resultComment, String code) {
            this.result = result;
            this.resultComment = resultComment;
            this.code = code;
        }
    }

    private static final class GetResultResponse {
        private final boolean result;
        private final String resultComment;
        private final int resultCode;
        private final String registerZipArchiveBase64;
        private final String dumpFormatVersion;
        private final String operatorName;
        private final String inn;
        private GetResultResponse(boolean result, String resultComment, int resultCode,
                                  String registerZipArchiveBase64, String dumpFormatVersion, String operatorName, String inn) {
            this.result = result;
            this.resultComment = resultComment;
            this.resultCode = resultCode;
            this.registerZipArchiveBase64 = registerZipArchiveBase64;
            this.dumpFormatVersion = dumpFormatVersion;
            this.operatorName = operatorName;
            this.inn = inn;
        }
    }

    private static final class RknBusinessException extends IOException {
        private final int resultCode;
        private RknBusinessException(int resultCode, String message) {
            super(message);
            this.resultCode = resultCode;
        }
    }
}