package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.AppConfig;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static ru.galkov.Main.getConfig;

/**
 * Автоматическая загрузка выгрузки из реестра РKN через SOAP API.
 *
 * Формат запроса (согласно документации РKN):
 * POST на https://vigruzki.rkn.gov.ru/services/OperatorRequest/
 * Content-Type: text/xml; charset=utf-8
 * SOAPAction: "getDumpByCert"
 *
 * Тело запроса - SOAP-конверт с base64 подписью.
 *
 * @author s0506777@yandex.ru Galkov V.A.
 */
public final class RknAutoDownloader {
    private static final Logger logger = LoggerFactory.getLogger(RknAutoDownloader.class);

    private final String apiUrl;
    private final Path signatureFilePath;
    private final Path outputPath;
    private final Path tempZipPath;
    private final Duration updateInterval;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private ScheduledExecutorService scheduler;
    private Instant lastSuccessfulUpdate;
    private int consecutiveFailures = 0;

    private static final int CONNECT_TIMEOUT = 30_000;
    private static final int READ_TIMEOUT = 300_000;
    private static final String SOAP_ACTION = "getDumpByCert";
    private static final String NAMESPACE = "http://vigruzki.rkn.gov.ru/services/OperatorRequest/";

    public RknAutoDownloader() {
        AppConfig config = getConfig();

        this.apiUrl = config.get("blacklist.rkn.remote.wsdl-url");
        this.signatureFilePath = Paths.get(config.get("blacklist.rkn.remote.signature-file")).toAbsolutePath().normalize();
        this.outputPath = Paths.get(config.get("blacklist.rkn.remote.output-file")).toAbsolutePath().normalize();
        this.tempZipPath = Paths.get(config.get("blacklist.rkn.remote.temp-zip-file")).toAbsolutePath().normalize();
        this.updateInterval = Duration.ofHours(config.getInt("blacklist.rkn.remote.update-interval-hours"));

        logger.info("RknAutoDownloader: url={}, signature={}, output={}, interval={}h",
                apiUrl, signatureFilePath.getFileName(), outputPath.getFileName(), updateInterval.toHours());
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            logger.warn("RknAutoDownloader уже запущен");
            return;
        }

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "RKN-AutoDownloader-Thread");
            t.setDaemon(true);
            t.setUncaughtExceptionHandler((thread, ex) ->
                    logger.error("Необработанное исключение: {}", ex.getMessage(), ex)
            );
            return t;
        });

        scheduler.schedule(this::loadWithRetry, 5, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(this::loadWithRetry, updateInterval.toSeconds(), updateInterval.toSeconds(), TimeUnit.SECONDS);

        logger.info("RknAutoDownloader запущен (интервал: {} ч.)", updateInterval.toHours());
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) return;

        if (scheduler != null) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        logger.info("RknAutoDownloader остановлен (последняя успешная: {})",
                lastSuccessfulUpdate != null ? lastSuccessfulUpdate : "никогда");
    }

    private void loadWithRetry() {
        int maxRetries = 3;
        long retryDelayMs = 60_000;

        logger.info("=== Загрузка выгрузки РKN ===");

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                logger.info("--- Попытка {}/{} ---", attempt, maxRetries);
                loadDump();

                consecutiveFailures = 0;
                lastSuccessfulUpdate = Instant.now();
                logger.info("=== Загрузка РKN успешна ===");
                logger.info("Файл: {}", outputPath);
                return;

            } catch (Exception e) {
                consecutiveFailures++;
                logger.warn("Попытка {}/{} не удалась: {}", attempt, maxRetries, e.getMessage());
                logger.debug("Детали:", e);

                if (attempt < maxRetries) {
                    long delay = retryDelayMs * attempt;
                    logger.info("Повтор через {} мс", delay);
                    try { Thread.sleep(delay); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                } else {
                    logger.error("=== Все попытки исчерпаны (всего неудач: {}) ===", consecutiveFailures);
                    logger.error("Приложение работает без обновлений РKN");
                }
            }
        }
    }

    private void loadDump() throws Exception {
        logger.debug("[1/5] Проверка подписи...");
        if (!Files.exists(signatureFilePath)) {
            throw new FileNotFoundException("Подпись не найдена: " + signatureFilePath);
        }
        logger.info("[1/5] Подпись: {} ({} байт)", signatureFilePath.getFileName(), Files.size(signatureFilePath));

        logger.debug("[2/5] Чтение и кодирование подписи...");
        byte[] signatureBytes = Files.readAllBytes(signatureFilePath);
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
        logger.info("[2/5] Base64: {} символов", signatureBase64.length());

        logger.debug("[3/5] Формирование SOAP-запроса...");
        String soapRequest = createSoapRequest(signatureBase64);
        logger.info("[3/5] SOAP-запрос: {} байт", soapRequest.getBytes(StandardCharsets.UTF_8).length);
        logger.debug("[3/5] SOAP тело (первые 500 симв.):\n{}",
                soapRequest.length() > 500 ? soapRequest.substring(0, 500) + "..." : soapRequest);

        logger.debug("[4/5] Отправка запроса...");
        byte[] zipBytes = sendSoapRequest(soapRequest);
        logger.info("[4/5] Получен ZIP: {} байт", zipBytes.length);

        logger.debug("[5/5] Распаковка...");
        extractFromZip(zipBytes);
        logger.info("[5/5] Готово: {}", outputPath);
    }

    /**
     * Создание SOAP-конверта.
     */
    private String createSoapRequest(String signatureBase64) {
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        sb.append("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" ");
        sb.append("xmlns:ns=\"").append(NAMESPACE).append("\">");
        sb.append("<soapenv:Header/>");
        sb.append("<soapenv:Body>");
        sb.append("<ns:getDumpByCert>");
        sb.append("<ns:request>").append(signatureBase64).append("</ns:request>");
        sb.append("</ns:getDumpByCert>");
        sb.append("</soapenv:Body>");
        sb.append("</soapenv:Envelope>");
        return sb.toString();
    }

    /**
     * Отправка SOAP-запроса.
     */
    private byte[] sendSoapRequest(String soapBody) throws Exception {
        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setRequestMethod("POST");
        conn.setConnectTimeout(CONNECT_TIMEOUT);
        conn.setReadTimeout(READ_TIMEOUT);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
        conn.setRequestProperty("SOAPAction", SOAP_ACTION);
        conn.setRequestProperty("Accept", "application/zip, application/octet-stream");
        conn.setRequestProperty("User-Agent", "RKN-AutoDownloader/1.0");

        logger.info("[HTTP] URL: {}", apiUrl);
        logger.info("[HTTP] Method: POST");
        logger.info("[HTTP] Content-Type: text/xml; charset=utf-8");
        logger.info("[HTTP] SOAPAction: {}", SOAP_ACTION);

        byte[] requestBody = soapBody.getBytes(StandardCharsets.UTF_8);
        logger.debug("[HTTP] Отправка тела: {} байт", requestBody.length);

        long start = System.currentTimeMillis();
        try (OutputStream os = conn.getOutputStream()) {
            os.write(requestBody);
            os.flush();
        }
        long end = System.currentTimeMillis();
        logger.info("[HTTP] Отправлено за {} мс", (end - start));

        int status = conn.getResponseCode();
        logger.info("[HTTP] Статус: {}", status);
        logger.debug("[HTTP] Content-Type: {}", conn.getContentType());
        logger.debug("[HTTP] Content-Length: {}", conn.getContentLength());

        // Обработка различных статусов
        if (status == HttpURLConnection.HTTP_OK) {
            // Успех - читаем ZIP
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                int total = 0;
                try (InputStream is = conn.getInputStream()) {
                    while ((bytesRead = is.read(buffer)) != -1) {
                        baos.write(buffer, 0, bytesRead);
                        total += bytesRead;
                    }
                }
                logger.info("[HTTP] Получено: {} байт", total);
                return baos.toByteArray();
            } finally {
                conn.disconnect();
            }

        } else if (status == 503) {
            // Сервис временно недоступен
            String errorBody = readStream(conn.getErrorStream());
            logger.warn("[HTTP] 503 Service Unavailable - сервис РKN временно недоступен");
            logger.debug("[HTTP] Тело ответа:\n{}", errorBody);
            throw new IOException("HTTP 503: Сервис РKN временно недоступен. Попробуйте позже.");

        } else if (status == 500) {
            // Ошибка сервера
            String errorBody = readStream(conn.getErrorStream());
            logger.error("[HTTP] 500 Internal Server Error");
            logger.error("[HTTP] Тело ошибки:\n{}", errorBody);

            // Проверяем SOAP Fault
            if (errorBody.contains("SOAP-ENV:Fault")) {
                if (errorBody.contains("Client")) {
                    throw new IOException("HTTP 500: Ошибка клиента. Проверьте формат запроса и подпись.");
                } else if (errorBody.contains("Server")) {
                    throw new IOException("HTTP 500: Ошибка сервера РKN. Попробуйте позже.");
                }
            }
            throw new IOException("HTTP 500: Внутренняя ошибка сервера РKN");

        } else if (status == 401 || status == 403) {
            // Проблемы с авторизацией
            logger.error("[HTTP] {} - проблема с сертификатом/подписью", status);
            String errorBody = readStream(conn.getErrorStream());
            logger.debug("[HTTP] Тело ошибки:\n{}", errorBody);
            throw new IOException("HTTP " + status + ": Отказано в доступе. Проверьте сертификат.");

        } else {
            // Другие ошибки
            String errorBody = readStream(conn.getErrorStream());
            logger.error("[HTTP] Ошибка {}: {}", status, errorBody);
            throw new IOException("HTTP " + status + ": " + errorBody);
        }
    }

    private void extractFromZip(byte[] zipBytes) throws Exception {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                logger.debug("[ZIP] Элемент: {} ({} байт)", entry.getName(), entry.getSize());

                if (entry.getName().endsWith(".xml")) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = zis.read(buffer)) != -1) {
                        baos.write(buffer, 0, bytesRead);
                    }

                    byte[] xmlBytes = baos.toByteArray();
                    Path parent = outputPath.getParent();
                    if (parent != null && !Files.exists(parent)) Files.createDirectories(parent);

                    Files.write(outputPath, xmlBytes);
                    logger.info("[ZIP] Сохранено: {} ({} байт)", outputPath.getFileName(), xmlBytes.length);
                    return;
                }
                zis.closeEntry();
            }
        }
        throw new IOException("В ZIP не найден XML");
    }

    private String readStream(InputStream is) throws Exception {
        if (is == null) return "Пустой поток";
        try (BufferedReader r = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append("\n");
            return sb.toString();
        }
    }

    public Instant getLastSuccessfulUpdate() { return lastSuccessfulUpdate; }
    public int getConsecutiveFailures() { return consecutiveFailures; }
    public void forceLoad() { loadWithRetry(); }
}