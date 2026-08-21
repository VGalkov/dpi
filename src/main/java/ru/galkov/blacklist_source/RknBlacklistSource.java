package ru.galkov.blacklist_source;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;
import ru.galkov.util.BlacklistRule;
import ru.galkov.util.LocaleUtil;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;
import java.io.InputStream;
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
        logger.info(LocaleUtil.getString("rkn_reading_register"), xmlFile.toAbsolutePath());

        try (InputStream inputStream = Files.newInputStream(xmlFile)) {
            return parseRegisterXml(inputStream);
        }
    }

    private List<BlacklistRule> parseRegisterXml(InputStream inputStream) throws IOException {
        List<BlacklistRule> rules = new ArrayList<>();
        RknHandler handler = new RknHandler(rules);

        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);

            SAXParser parser = factory.newSAXParser();
            parser.parse(inputStream, handler);
        } catch (Exception e) {
            throw new IOException(LocaleUtil.getString("rkn_xml_parse_error"), e);
        }

        logger.info(LocaleUtil.getString("rkn_rules_extracted"), rules.size());
        return rules;
    }

    private static class RknHandler extends DefaultHandler {
        private final List<BlacklistRule> rules;
        private String currentContentId;
        private String currentBlockType;
        private final StringBuilder currentText = new StringBuilder(256);

        RknHandler(List<BlacklistRule> rules) {
            this.rules = rules;
        }

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) {
            if ("content".equals(qName)) {
                currentContentId = attributes.getValue("id");
                currentBlockType = null;
            }

            currentText.setLength(0);
        }

        @Override
        public void characters(char[] ch, int start, int length) {
            currentText.append(ch, start, length);
        }

        @Override
        public void endElement(String uri, String localName, String qName) {
            if ("content".equals(qName)) {
                currentContentId = null;
                currentBlockType = null;
            } else if ("blockType".equals(qName)) {
                currentBlockType = currentText.toString().trim();
            } else if (("domain".equals(qName) || "ip".equals(qName) || "ipv6".equals(qName))
                    && currentContentId != null) {
                String value = currentText.toString().trim();

                if (!value.isBlank()) {
                    BlacklistRule.RuleType type = "domain".equals(qName)
                            ? BlacklistRule.RuleType.DOMAIN
                            : BlacklistRule.RuleType.IP;

                    if (value.startsWith("*.")) value = value.substring(2);

                    rules.add(new BlacklistRule(
                            type,
                            value.toLowerCase(Locale.ROOT),
                            "RKN",
                            currentContentId,
                            currentBlockType
                    ));
                }
            }
        }
    }

    @Override
    public String toString() {
        return "RknBlacklistSource{xmlFile=" + xmlFile + '}';
    }
}