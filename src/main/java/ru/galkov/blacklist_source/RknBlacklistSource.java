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
        Document doc = parseXml(xmlBytes);
        NodeList contentNodes = doc.getElementsByTagNameNS("*", "content");
        for (int c = 0; c < contentNodes.getLength(); c++) {
            Node content = contentNodes.item(c);
            String contentId = extractContentId(content);
            String blockType = extractBlockType(content);
            for (Node node = content.getFirstChild(); node != null; node = node.getNextSibling()) {
                String tag = node.getNodeName();
                String value = node.getTextContent().trim();
                if (value.isBlank()) continue;
                BlacklistRule.RuleType type = "domain".equals(tag) ? BlacklistRule.RuleType.DOMAIN
                        : ("ip".equals(tag) || "ipv6".equals(tag)) ? BlacklistRule.RuleType.IP : null;
                if (type == null) continue;
                if (value.startsWith("*.")) value = value.substring(2);
                rules.add(new BlacklistRule(type, value.toLowerCase(Locale.ROOT), "RKN", contentId, blockType));
            }
        }
        logger.info(LocaleUtil.getString("rkn_rules_extracted"), rules.size());
        return rules;
    }

    private String extractContentId(Node content) {
        NamedNodeMap attrs = content.getAttributes();
        if (attrs == null) return null;
        Node idAttr = attrs.getNamedItem("id");
        return idAttr != null ? idAttr.getNodeValue() : null;
    }

    private String extractBlockType(Node content) {
        for (Node n = content.getFirstChild(); n != null; n = n.getNextSibling())
            if ("blockType".equals(n.getNodeName())) return n.getTextContent().trim();
        return null;
    }

    private Document parseXml(byte[] xmlBytes) throws IOException {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            return f.newDocumentBuilder().parse(new ByteArrayInputStream(xmlBytes));
        } catch (Exception e) {
            throw new IOException(LocaleUtil.getString("rkn_xml_parse_error"), e);
        }
    }

    @Override
    public String toString() { return "RknBlacklistSource{xmlFile=" + xmlFile + '}'; }
}