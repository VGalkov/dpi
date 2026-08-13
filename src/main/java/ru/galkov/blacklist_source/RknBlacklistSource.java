package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
/**
 * s0506777@yandex.ru Galkov V.A.
 */
public final class RknBlacklistSource implements BlacklistSource {

    private static final Logger logger = LoggerFactory.getLogger(RknBlacklistSource.class);
    private final Path xmlFile;

    public RknBlacklistSource(Path xmlFile) {
        if (xmlFile == null || !Files.isRegularFile(xmlFile))
            throw new IllegalArgumentException("Файл XML РКН не задан или не найден: " + xmlFile);
        this.xmlFile = xmlFile;
    }

    @Override
    public List<String> loadRules() throws IOException {
        byte[] xmlBytes = Files.readAllBytes(xmlFile);
        logger.info("Чтение реестра РКН из файла: {}", xmlFile.toAbsolutePath());
        return parseRegisterXml(xmlBytes);
    }

    private List<String> parseRegisterXml(byte[] xmlBytes) throws IOException {
        List<String> rules = new ArrayList<>();
        Document document = parseXml(xmlBytes);

        NodeList contentNodes = document.getElementsByTagNameNS("*", "content");

        for (int c = 0; c < contentNodes.getLength(); c++) {
            var content = contentNodes.item(c);
            var children = content.getChildNodes();

            for (int i = 0; i < children.getLength(); i++) {
                var node = children.item(i);
                String tagName = node.getNodeName();

                switch (tagName) {
                    case "domain" -> {
                        String domain = node.getTextContent().trim().toLowerCase(Locale.ROOT);
                        if (domain.startsWith("*.")) {
                            domain = domain.substring(2);
                        }
                        if (!domain.isBlank()) {
                            rules.add(domain);
                        }
                    }
                    case "ip" -> {
                        String ip = node.getTextContent().trim();
                        if (!ip.isBlank()) {
                            rules.add(ip);
                        }
                    }
                    case "ipv6" -> {
                        String ipv6 = node.getTextContent().trim();
                        if (!ipv6.isBlank()) {
                            rules.add(ipv6);
                        }
                    }
                }
            }
        }

        logger.info("Из файла РКН извлечено правил: {}", rules.size());
        return rules;
    }

    private Document parseXml(byte[] xmlBytes) throws IOException {
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

    @Override
    public String toString() {
        return "RknBlacklistSource{xmlFile=" + xmlFile + '}';
    }
}