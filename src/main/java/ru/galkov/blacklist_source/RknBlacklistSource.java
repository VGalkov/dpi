package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.galkov.util.BlacklistRule;
import ru.galkov.util.LocaleUtil;

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
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class RknBlacklistSource implements BlacklistSource {

    private static final Logger logger = LoggerFactory.getLogger(RknBlacklistSource.class);
    private final Path xmlFile;

    public RknBlacklistSource(Path xmlFile) {
        if (xmlFile == null || !Files.isRegularFile(xmlFile))
            throw new IllegalArgumentException(LocaleUtil.getString("rkn_xml_file_not_found", xmlFile));
        this.xmlFile = xmlFile;
    }

    @Override
    public List<BlacklistRule> loadRules() throws IOException {
        byte[] xmlBytes = Files.readAllBytes(xmlFile);
        logger.info(LocaleUtil.getString("rkn_reading_register"), xmlFile.toAbsolutePath());
        return parseRegisterXml(xmlBytes);
    }

    private List<BlacklistRule> parseRegisterXml(byte[] xmlBytes) throws IOException {
        List<BlacklistRule> rules = new ArrayList<>();
        Document document = parseXml(xmlBytes);

        NodeList contentNodes = document.getElementsByTagNameNS("*", "content");

        for (int c = 0; c < contentNodes.getLength(); c++) {
            Node content = contentNodes.item(c);
            NodeList children = content.getChildNodes();

            String contentId = extractContentId(content);
            String blockType = extractBlockType(content);

            for (int i = 0; i < children.getLength(); i++) {
                Node node = children.item(i);
                String tagName = node.getNodeName();

                switch (tagName) {
                    case "domain" -> {
                        String domain = node.getTextContent().trim().toLowerCase(Locale.ROOT);
                        if (domain.startsWith("*.")) {
                            domain = domain.substring(2);
                        }
                        if (!domain.isBlank()) {
                            rules.add(new BlacklistRule(
                                    BlacklistRule.RuleType.DOMAIN,
                                    domain,
                                    "RKN",
                                    contentId,
                                    blockType
                            ));
                        }
                    }
                    case "ip" -> {
                        String ip = node.getTextContent().trim();
                        if (!ip.isBlank()) {
                            rules.add(new BlacklistRule(
                                    BlacklistRule.RuleType.IP,
                                    ip,
                                    "RKN",
                                    contentId,
                                    blockType
                            ));
                        }
                    }
                    case "ipv6" -> {
                        String ipv6 = node.getTextContent().trim();
                        if (!ipv6.isBlank()) {
                            rules.add(new BlacklistRule(
                                    BlacklistRule.RuleType.IP,
                                    ipv6,
                                    "RKN",
                                    contentId,
                                    blockType
                            ));
                        }
                    }
                }
            }
        }

        logger.info(LocaleUtil.getString("rkn_rules_extracted"), rules.size());
        return rules;
    }

    private String extractContentId(Node content) {
        NamedNodeMap attributes = content.getAttributes();

        if (attributes == null)
            return null;

        Node idAttr = attributes.getNamedItem("id");

        return idAttr != null ? idAttr.getNodeValue() : null;
    }

    private String extractBlockType(Node content) {
        NodeList children = content.getChildNodes();

        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);

            if ("blockType".equals(node.getNodeName()))
                return node.getTextContent().trim();
        }

        return null;
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
            throw new IOException(LocaleUtil.getString("rkn_xml_parse_error"), e);
        }
    }

    @Override
    public String toString() {
        return "RknBlacklistSource{xmlFile=" + xmlFile + '}';
    }
}