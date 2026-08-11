package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import ru.galkov.servers.RknRequestSigner;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

    public final class RknBlacklistSource implements BlacklistSource {

    private static final Logger logger = LoggerFactory.getLogger(RknBlacklistSource.class);
    private static final String SOAP_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String RKN_NAMESPACE = "http://vigruzki.rkn.gov.ru/OperatorRequest/";

    private final String endpoint;
    private final Path requestFile;
    private final Path signatureFile;
    private final int pollIntervalSeconds;
    private final int pollTimeoutSeconds;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;
    private final Path emchdFile;
    private final String emchdFileName;
    private final Path emchdSignatureFile;
    private final boolean emchdEnabled;
    private final String operatorName;
    private final String inn;
    private final String ogrn;
    private final String email;
    private final String timezone;
    private final RknRequestSigner requestSigner;

    public RknBlacklistSource(String endpoint, Path requestFile, Path signatureFile, boolean emchdEnabled, Path emchdFile, String emchdFileName, Path emchdSignatureFile, int pollIntervalSeconds, int pollTimeoutSeconds, int connectTimeoutMillis, int readTimeoutMillis, String operatorName, String inn, String ogrn, String email, String timezone, RknRequestSigner requestSigner) {
        this.endpoint = endpoint;
        this.requestFile = requestFile;
        this.signatureFile = signatureFile;
        this.emchdEnabled = emchdEnabled;
        this.emchdFile = emchdFile;
        this.emchdFileName = emchdFileName;
        this.emchdSignatureFile = emchdSignatureFile;
        this.pollIntervalSeconds = pollIntervalSeconds;
        this.pollTimeoutSeconds = pollTimeoutSeconds;
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;
        this.operatorName = operatorName;
        this.inn = inn;
        this.ogrn = ogrn;
        this.email = email;
        this.timezone = timezone;
        this.requestSigner = requestSigner;
    }

        @Override
        public List<String> loadRules() throws IOException {
            validateFiles();

            if (requestSigner == null) {
                throw new IOException("Не задан RknRequestSigner");
            }

            byte[] requestBytes = createRequestBytes();
            byte[] signatureBytes;

            try {
                signatureBytes = requestSigner.sign(requestBytes);
            } catch (Exception e) {
                throw new IOException("Не удалось подписать XML-запрос РКН", e);
            }

            saveFile(requestFile, requestBytes);
            saveFile(signatureFile, signatureBytes);

            String requestBase64 = Base64.getEncoder().encodeToString(requestBytes);
            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

            String emchdBase64 = null;
            String emchdSignatureBase64 = null;

            if (emchdEnabled) {
                emchdBase64 = Base64.getEncoder().encodeToString(Files.readAllBytes(emchdFile));
                emchdSignatureBase64 = Base64.getEncoder().encodeToString(Files.readAllBytes(emchdSignatureFile));
            }

            String sendRequestSoap = createSendRequestSoap(requestBase64, signatureBase64, emchdBase64, emchdFileName, emchdSignatureBase64);

            Document sendResponse = postSoap(sendRequestSoap, endpoint + "sendRequest");

            boolean accepted = readBoolean(sendResponse, "result");
            String comment = readText(sendResponse, "resultComment");
            String code = readText(sendResponse, "code");

            if (!accepted || code == null || code.isBlank()) {
                throw new IOException("РКН отклонил запрос: result=" + accepted + ", comment=" + comment);
            }

            logger.info("Запрос РКН принят, код: {}", code);

            byte[] archive = waitForResult(code);
            return parseRegisterArchive(archive);
        }


        private byte[] createRequestBytes() {
            ZonedDateTime now = ZonedDateTime.now(ZoneId.of(timezone));
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");

            String xml = "<?xml version=\"1.0\" encoding=\"windows-1251\"?>" +
                    "<request>" +
                    "<requestTime>" + formatter.format(now) + "</requestTime>" +
                    "<operatorName>" + escapeXml(operatorName) + "</operatorName>" +
                    "<inn>" + escapeXml(inn) + "</inn>" +
                    "<ogrn>" + escapeXml(ogrn) + "</ogrn>" +
                    "<email>" + escapeXml(email) + "</email>" +
                    "</request>";

            return xml.getBytes(Charset.forName("windows-1251"));
        }

    private static void saveFile(Path path, byte[] data) throws IOException {
        if (path == null) {
            return;
        }

        Path parent = path.toAbsolutePath().getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        Files.write(path, data);
    }
        private void validateFiles() throws IOException {
            if (requestFile == null) {
                throw new IOException("Не задан путь к файлу запроса РКН");
            }

            if (signatureFile == null) {
                throw new IOException("Не задан путь к подписи запроса РКН");
            }

            if (emchdEnabled) {
                requireFile(emchdFile, "Файл МЧД РКН");
                requireFile(emchdSignatureFile, "Подпись МЧД РКН");

                if (emchdFileName == null || emchdFileName.isBlank()) {
                    throw new IOException("Не задано имя файла МЧД");
                }
            }
        }
    private void requireFile(
            Path path,
            String description) throws IOException {

        if (path == null || !Files.isRegularFile(path)) {
            throw new IOException(description + " не найден: " + (path == null ? "null" : path.toAbsolutePath()));
        }
    }
    private byte[] waitForResult(String code) throws IOException {

        long deadline = System.currentTimeMillis() + Duration.ofSeconds(pollTimeoutSeconds).toMillis();
        String lastComment = null;
        while (System.currentTimeMillis() < deadline) {
            Document response =
                    postSoap(
                            createGetResultSoap(code),
                            "http://vigruzki.rkn.gov.ru/services/OperatorRequest/getResult"
                    );

            boolean result = readBoolean(response, "result");
            String comment = readText(response, "resultComment");
            if (comment != null && !comment.isBlank()) {
                lastComment = comment;
                logger.info("Статус запроса РКН {}: {}", code, comment);
            }

            String archiveBase64 = readText(response, "registerZipArchive");
            if (archiveBase64 != null && !archiveBase64.isBlank()) {

                try {
                    return Base64.getMimeDecoder().decode(archiveBase64);
                } catch (IllegalArgumentException e) {
                    throw new IOException("РКН вернул некорректный Base64-архив", e);
                }
            }

            if (result && archiveBase64 == null) {
                logger.warn("РКН сообщил об успешном результате, но архив отсутствует. Код запроса: {}", code);
            }

            try {
                Thread.sleep(pollIntervalSeconds * 1000L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Ожидание результата РКН прервано", e);
            }
        }

        throw new IOException(
                "РКН не вернул выгрузку за " +
                        pollTimeoutSeconds +
                        " секунд. Код запроса: " +
                        code +
                        ". Последний статус: " +
                        lastComment
        );
    }

    private List<String> parseRegisterArchive(
            byte[] archiveBytes) throws IOException {

        List<String> rules = new ArrayList<String>();

        try (
                ByteArrayInputStream input = new ByteArrayInputStream(archiveBytes);
                ZipInputStream zip = new ZipInputStream(input)
        ) {
            ZipEntry entry;

            while ((entry = zip.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }

                String name = entry.getName().toLowerCase(Locale.ROOT);

                if (!name.endsWith(".xml")) {
                    continue;
                }

                byte[] xmlBytes = readAllBytes(zip);
                rules.addAll(parseRegisterXml(xmlBytes));
            }
        }

        logger.info("Из выгрузки РКН извлечено правил: {}", rules.size());
        return rules;
    }

    private List<String> parseRegisterXml(byte[] xmlBytes) throws IOException {

        List<String> rules = new ArrayList<String>();
        Document document = parseXml(xmlBytes);
        NodeList domains = document.getElementsByTagNameNS("*", "domain");

        for (int i = 0; i < domains.getLength(); i++) {

            String domain =
                    domains.item(i)
                            .getTextContent()
                            .trim()
                            .toLowerCase(Locale.ROOT);

            if (domain.startsWith("*.")) {
                domain = domain.substring(2);
            }

            if (!domain.isBlank()) {
                rules.add(domain);
            }
        }

        NodeList ipv4 = document.getElementsByTagNameNS("*", "ip");

        for (int i = 0; i < ipv4.getLength(); i++) {

            String ip = ipv4.item(i).getTextContent().trim();
            if (!ip.isBlank()) {
                rules.add(ip);
            }
        }

        NodeList ipv6 = document.getElementsByTagNameNS("*", "ipv6");

        for (int i = 0; i < ipv6.getLength(); i++) {

            String ip = ipv6.item(i).getTextContent().trim();
            if (!ip.isBlank()) {
                rules.add(ip);
            }
        }
        return rules;
    }

    private Document parseXml(
            byte[] xmlBytes) throws IOException {

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(new ByteArrayInputStream(xmlBytes));

        } catch (Exception e) {
            throw new IOException("Ошибка разбора XML РКН", e);
        }
    }

    private Document postSoap(
            String soapXml,
            String soapAction) throws IOException {

        HttpURLConnection connection = (HttpURLConnection) URI.create(endpoint).toURL().openConnection();

        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setConnectTimeout(connectTimeoutMillis);
        connection.setReadTimeout(readTimeoutMillis);
        connection.setRequestProperty(
                "Content-Type",
                "text/xml; charset=utf-8"
        );
        connection.setRequestProperty(
                "SOAPAction",
                "\"" + soapAction + "\""
        );
        connection.setRequestProperty(
                "User-Agent",
                "Galkov-DnsProxy/1.0"
        );

        byte[] requestBytes = soapXml.getBytes(Charset.forName("UTF-8"));
        connection.getOutputStream().write(requestBytes);
        int status = connection.getResponseCode();
        InputStream responseStream =
                status >= 400 ? connection.getErrorStream() : connection.getInputStream();

        if (responseStream == null) {
            throw new IOException("РКН вернул HTTP-код " + status + " без тела ответа");
        }

        try (InputStream input = responseStream) {
            byte[] responseBytes = readAllBytes(input);

            if (status >= 400) {
                throw new IOException(
                        "РКН вернул HTTP-код " + status +
                                ": " +
                                new String(
                                        responseBytes,
                                        StandardCharsets.UTF_8
                                )
                );
            }

            return parseXml(responseBytes);

        } finally {
            connection.disconnect();
        }
    }

    private String createSendRequestSoap(String requestBase64, String signatureBase64, String emchdBase64, String emchdFileName, String emchdSignatureBase64) {
        StringBuilder xml = new StringBuilder();

        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        xml.append("<soapenv:Envelope xmlns:soapenv=\"").append(SOAP_NAMESPACE).append("\" xmlns:rkn=\"").append(RKN_NAMESPACE).append("\">");
        xml.append("<soapenv:Body>");
        xml.append("<rkn:sendRequest>");
        xml.append("<rkn:requestFile>").append(requestBase64).append("</rkn:requestFile>");
        xml.append("<rkn:signatureFile>").append(signatureBase64).append("</rkn:signatureFile>");

        if (emchdEnabled) {
            xml.append("<rkn:emchdFile>").append(emchdBase64).append("</rkn:emchdFile>");
            xml.append("<rkn:emchdFileName>").append(escapeXml(emchdFileName)).append("</rkn:emchdFileName>");
            xml.append("<rkn:emchdSignatureFile>").append(emchdSignatureBase64).append("</rkn:emchdSignatureFile>");
        }

        xml.append("</rkn:sendRequest>");
        xml.append("</soapenv:Body>");
        xml.append("</soapenv:Envelope>");

        return xml.toString();
    }

    private String createGetResultSoap(
            String code) {

        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<soapenv:Envelope " +
                "xmlns:soapenv=\"" + SOAP_NAMESPACE + "\" " +
                "xmlns:rkn=\"" + RKN_NAMESPACE + "\">" +
                "<soapenv:Body>" +
                "<rkn:getResult>" +
                "<rkn:code>" +
                escapeXml(code) +
                "</rkn:code>" +
                "</rkn:getResult>" +
                "</soapenv:Body>" +
                "</soapenv:Envelope>";
    }

    private static String escapeXml(String value) {
        if (value == null) {
            return "";
        }

        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;");
    }

    private static String readText(
            Document document,
            String localName) {

        NodeList nodes = document.getElementsByTagNameNS("*", localName);
        if (nodes.getLength() == 0) {
            return null;
        }

        String value = nodes.item(0).getTextContent().trim();
        return value.isEmpty() ? null : value;
    }

    private static boolean readBoolean(Document document, String localName) {

        String value = readText(document, localName);
        return Boolean.parseBoolean(value);
    }

    private static byte[] readAllBytes(InputStream input) throws IOException {

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) != -1) {output.write(buffer, 0, count);
        }

        return output.toByteArray();
    }

    @Override
    public String toString() {
        return "RknBlacklistSource{" +
                "endpoint='" + endpoint + '\'' +
                ", requestFile=" + requestFile +
                ", signatureFile=" + signatureFile +
                '}';
    }
}