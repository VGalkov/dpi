package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import ru.galkov.util.BlacklistRule;
import ru.galkov.util.LocaleUtil;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class RknRemoteBlacklistSource implements BlacklistSource {
    private static final Logger logger = LoggerFactory.getLogger(RknRemoteBlacklistSource.class);
    //private static final String SERVICE_URL = "https://vigruzki.rkn.gov.ru/services/OperatorRequestTest/";
    private static final XPath X_PATH = XPathFactory.newInstance().newXPath();
    private static final String SERVICE_URL = "https://vigruzki.rkn.gov.ru/services/OperatorRequest/";

    private final String operatorName;
    private final String inn;
    private final byte[] requestFileBytes;
    private final byte[] signatureFileBytes;
    private final byte[] emchdFileBytes;
    private final String emchdFileName;
    private final byte[] emchdSignatureFileBytes;

    public RknRemoteBlacklistSource(String operatorName, String inn,
                                    byte[] requestFile, byte[] signature,
                                    byte[] emchd, String emchdName, byte[] emchdSig) {
        this.operatorName = operatorName;
        this.inn = inn;
        this.requestFileBytes = requestFile;
        this.signatureFileBytes = signature;
        this.emchdFileBytes = emchd;
        this.emchdFileName = emchdName;
        this.emchdSignatureFileBytes = emchdSig;
    }

    public List<BlacklistRule> loadRules() {
        logger.info(LocaleUtil.getString("rkn_remote_load_start"), operatorName, inn);
        try {
            LastDumpInfo info = callGetLastDumpDateEx();
            if (info.lastDumpDateUrgently == 0) {
                logger.warn(LocaleUtil.getString("rkn_dump_date_missing"));
                return Collections.emptyList();
            }

            SendRequestResult sendResult = callSendRequest(info.dumpFormatVersion);
            if (!sendResult.isResult) {
                logger.error(LocaleUtil.getString("rkn_send_request_failed"), sendResult.resultCode, sendResult.resultComment);
                return Collections.emptyList();
            }
            String code = sendResult.code;
            logger.info(LocaleUtil.getString("rkn_request_sent"), code);

            GetResultResult getResult = pollResult(code);
            if (!getResult.isResult || getResult.resultCode != 1) {
                logger.error(LocaleUtil.getString("rkn_get_result_failed"), getResult.resultCode, getResult.resultComment);
                return Collections.emptyList();
            }

            return processZipArchive(getResult.registerZipArchive);
        } catch (IOException e) {
            logger.error(LocaleUtil.getString("rkn_network_error"), e.getMessage(), e);
            return Collections.emptyList();
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("rkn_unexpected_error"), e.toString(), e);
            return Collections.emptyList();
        }
    }

    private LastDumpInfo callGetLastDumpDateEx() throws Exception {
        int maxRetries = 3;
        int retryDelayMs = 5000;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                String soapBody = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tns=\"http://rsoc.ru\">" +
                        "<soap:Body><tns:getLastDumpDateEx/></soap:Body></soap:Envelope>";
                return parseLastDumpDateExResponse(sendSoapRequest(soapBody));
            } catch (IOException e) {
                if (attempt == maxRetries) throw e;
                logger.warn("Попытка {} не удалась, повтор через {} мс: {}", attempt, retryDelayMs, e.getMessage());
                Thread.sleep(retryDelayMs);
            }
        }
        throw new IllegalStateException("Не удалось выполнить запрос после " + maxRetries + " попыток");
    }

    private SendRequestResult callSendRequest(String dumpFormatVersion) throws Exception {
        String reqBase64 = (requestFileBytes == null || requestFileBytes.length == 0) ? "" : Base64.getEncoder().encodeToString(requestFileBytes);
        String sigBase64 = (signatureFileBytes == null || signatureFileBytes.length == 0) ? "" : Base64.getEncoder().encodeToString(signatureFileBytes);
        String emchdBase64 = "";
        String emchdSigBase64 = "";

        if (emchdFileBytes != null && emchdFileBytes.length > 0) {
            emchdBase64 = Base64.getEncoder().encodeToString(emchdFileBytes);
            emchdSigBase64 = (emchdSignatureFileBytes != null) ? Base64.getEncoder().encodeToString(emchdSignatureFileBytes) : "";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tns=\"http://rsoc.ru\">");
        sb.append("<soap:Body><tns:sendRequest>");
        sb.append("<requestFile>").append(reqBase64).append("</requestFile>");
        sb.append("<signatureFile>").append(sigBase64).append("</signatureFile>");
        if (!emchdBase64.isEmpty()) {
            sb.append("<emchdFile>").append(emchdBase64).append("</emchdFile>");
            sb.append("<emchdFileName>").append(escapeXml(emchdFileName)).append("</emchdFileName>");
            sb.append("<emchdSignatureFile>").append(emchdSigBase64).append("</emchdSignatureFile>");
        }
        sb.append("<dumpFormatVersion>").append(dumpFormatVersion).append("</dumpFormatVersion>");
        sb.append("</tns:sendRequest></soap:Body></soap:Envelope>");

        return parseSendRequestResponse(sendSoapRequest(sb.toString()));
    }

    private GetResultResult pollResult(String code) throws Exception {
        int attempts = 0;
        int maxAttempts = 15;
        int pollIntervalSeconds = 60;

        while (attempts < maxAttempts) {
            String soapBody = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tns=\"http://rsoc.ru\">" +
                    "<soap:Body><tns:getResult><code>" + escapeXml(code) + "</code></tns:getResult></soap:Body></soap:Envelope>";

            GetResultResult result = parseGetResultResponse(sendSoapRequest(soapBody));
            if (result.isResult && result.resultCode == 1) return result;
            if (result.resultCode == 0) {
                attempts++;
                logger.info(LocaleUtil.getString("rkn_result_not_ready"), result.resultCode, pollIntervalSeconds);
                Thread.sleep(pollIntervalSeconds * 1000L);
                continue;
            }
            throw new IllegalStateException(LocaleUtil.getString("rkn_result_error", result.resultCode, result.resultComment));
        }
        throw new IllegalStateException(LocaleUtil.getString("rkn_poll_timeout", code));
    }

    private String sendSoapRequest(String soapXml) throws IOException {
        java.net.URL url = new java.net.URL(SERVICE_URL);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(60000);
        conn.addRequestProperty("Content-Type", "text/xml; charset=utf-8");
        conn.addRequestProperty("SOAPAction", "");
        conn.addRequestProperty("User-Agent", "MyRknLoader/1.0");

        try (OutputStream os = conn.getOutputStream()) {
            os.write(soapXml.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();
        InputStream inputStream = (conn.getErrorStream() != null) ? conn.getErrorStream() : conn.getInputStream();

        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) response.append(line);
        } finally {
            conn.disconnect();
        }

        String respStr = response.toString();
        logger.debug("RKN HTTP Response: code={}, response={}", responseCode, respStr);

        if (responseCode == 503) {
            logger.warn(LocaleUtil.getString("rkn_service_unavailable"));
            logger.debug("Ответ сервера: {}", respStr);
            throw new IOException(LocaleUtil.getString("rkn_service_unavailable_msg"));
        }
        if (responseCode >= 400 && !respStr.contains("<soap:Fault>")) {
            logger.error(LocaleUtil.getString("rkn_http_error"), responseCode, conn.getResponseMessage());
            throw new IOException(LocaleUtil.getString("rkn_http_error", responseCode, conn.getResponseMessage()));
        }
        return respStr;
    }

    private List<BlacklistRule> processZipArchive(String zipBase64Data) throws IOException {
        if (zipBase64Data == null || zipBase64Data.trim().isEmpty()) throw new IOException(LocaleUtil.getString("rkn_empty_zip"));

        byte[] zipBytes = Base64.getDecoder().decode(zipBase64Data);
        List<BlacklistRule> rules = new ArrayList<>();

        try (InputStream zipInputStream = new ByteArrayInputStream(zipBytes);
             ZipInputStream zis = new ZipInputStream(zipInputStream)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().toLowerCase().endsWith(".xml")) {
                    logger.info(LocaleUtil.getString("rkn_xml_found"), entry.getName());
                    rules.addAll(parseXmlFromStream(zis));
                }
                zis.closeEntry();
            }
        } catch (Exception e) {
            throw new IOException(LocaleUtil.getString("rkn_zip_process_error"), e);
        }
        logger.info(LocaleUtil.getString("rkn_rules_parsed", rules.size()));
        return rules;
    }

    private List<BlacklistRule> parseXmlFromStream(InputStream is) throws IOException {
        List<BlacklistRule> rules = new ArrayList<>(1000);
        RknHandler handler = new RknHandler(rules);

        try {
            javax.xml.parsers.SAXParserFactory factory = javax.xml.parsers.SAXParserFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);

            javax.xml.parsers.SAXParser parser = factory.newSAXParser();
            parser.parse(is, handler);
        } catch (Exception e) {
            throw new IOException(LocaleUtil.getString("rkn_xml_parse_error"), e);
        }
        return rules;
    }

    private LastDumpInfo parseLastDumpDateExResponse(String xml) throws Exception {
        LastDumpInfo info = new LastDumpInfo();
        info.lastDumpDateUrgently = extractLongSafe(xml, "lastDumpDateUrgently");
        info.dumpFormatVersion = extractStringSafe(xml, "dumpFormatVersion");
        return info;
    }

    private SendRequestResult parseSendRequestResponse(String xml) throws Exception {
        SendRequestResult res = new SendRequestResult();
        res.isResult = Boolean.parseBoolean(extractStringSafe(xml, "result"));
        res.code = extractStringSafe(xml, "code");
        res.resultCode = Integer.parseInt(extractStringSafe(xml, "resultCode"));
        res.resultComment = extractStringSafe(xml, "resultComment");
        return res;
    }

    private GetResultResult parseGetResultResponse(String xml) throws Exception {
        GetResultResult res = new GetResultResult();
        res.isResult = Boolean.parseBoolean(extractStringSafe(xml, "result"));
        res.resultCode = Integer.parseInt(extractStringSafe(xml, "resultCode"));
        res.resultComment = extractStringSafe(xml, "resultComment");
        res.registerZipArchive = extractStringSafe(xml, "registerZipArchive");
        return res;
    }

    private String extractStringSafe(String xml, String tagName) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            NodeList nodes = (NodeList) X_PATH.evaluate("//" + tagName, doc, XPathConstants.NODESET);
            if (nodes.getLength() > 0) {
                String val = nodes.item(0).getTextContent();
                return (val != null) ? val.trim() : "";
            }
        } catch (Exception ignored) {}
        return "";
    }

    private long extractLongSafe(String xml, String tagName) {
        String val = extractStringSafe(xml, tagName);
        if (val.isEmpty()) return 0L;
        try { return Long.parseLong(val); } catch (NumberFormatException e) { return 0L; }
    }

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

    private static class LastDumpInfo { long lastDumpDateUrgently; String dumpFormatVersion; }
    private static class SendRequestResult { boolean isResult; String code; int resultCode; String resultComment; }
    private static class GetResultResult { boolean isResult; int resultCode; String resultComment; String registerZipArchive; }

    private static class RknHandler extends org.xml.sax.helpers.DefaultHandler {
        private final List<BlacklistRule> rules;
        private String currentContentId;
        private String currentBlockType;
        private final StringBuilder currentText = new StringBuilder(256);

        RknHandler(List<BlacklistRule> rules) { this.rules = rules; }

        @Override public void startElement(String uri, String localName, String qName, org.xml.sax.Attributes attributes) {
            if ("content".equals(qName)) {
                currentContentId = attributes.getValue("id");
                currentBlockType = null;
            }
            currentText.setLength(0);
        }

        @Override public void characters(char[] ch, int start, int length) { currentText.append(ch, start, length); }

        @Override public void endElement(String uri, String localName, String qName) {
            if ("content".equals(qName)) { currentContentId = null; currentBlockType = null; }
            else if ("blockType".equals(qName)) currentBlockType = currentText.toString().trim();
            else if (("domain".equals(qName) || "ip".equals(qName) || "ipv6".equals(qName) || "ipSubnet".equals(qName)) && currentContentId != null) {
                String value = currentText.toString().trim();
                if (value.isBlank()) return;
                BlacklistRule.RuleType type = "domain".equals(qName) ? BlacklistRule.RuleType.DOMAIN : BlacklistRule.RuleType.IP;
                if ("domain".equals(qName) && value.startsWith("*.")) value = value.substring(2);
                rules.add(new BlacklistRule(type, value.toLowerCase(java.util.Locale.ROOT), "RKN_REMOTE", currentContentId, currentBlockType));
            }
        }
    }

    @Override public String toString() { return "RknRemoteBlacklistSource{operator=" + operatorName + ", inn=" + inn + "}"; }
}