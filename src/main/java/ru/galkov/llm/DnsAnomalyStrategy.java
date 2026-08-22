package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * Стратегия для DNS-аномалий.
 */
public class DnsAnomalyStrategy implements AnomalyStrategy<DnsQueryRecord> {
    private static final Logger logger = LoggerFactory.getLogger(DnsAnomalyStrategy.class);
    private final String promptTemplate;
    private final String configPrefix;

    public DnsAnomalyStrategy(String configPrefix) {
        this.configPrefix = configPrefix;
        this.promptTemplate = loadPromptTemplate("prompts/dns_anomaly_prompt.txt");
    }

    @Override
    public String buildPrompt(DnsQueryRecord record) {
        if (record.getQueryType() == 12) {
            logger.debug("Skipping PTR query for domain={}", record.getDomain());
            return "";
        }
        String domain = record.getDomain();
        return promptTemplate
                .replace("{clientIp}", escapePlaceholder(record.getClientIp()))
                .replace("{domain}", escapePlaceholder(domain))
                .replace("{queryType}", String.valueOf(record.getQueryType()))
                .replace("{timestamp}", String.valueOf(record.getTimestamp()))
                .replace("{qr}", record.isQuery() ? "QUERY" : "RESPONSE")
                .replace("{opcode}", String.valueOf(record.getOpcode()))
                .replace("{tc}", record.isTruncated() ? "true" : "false")
                .replace("{rd}", record.isRecursionDesired() ? "true" : "false")
                .replace("{z}", String.valueOf(record.getZ()))
                .replace("{rcode}", String.valueOf(record.getRcode()))
                .replace("{domainLength}", String.valueOf(record.getDomainLength()))
                .replace("{entropy}", formatDouble(record.getEntropy()))
                .replace("{subdomainCount}", String.valueOf(record.getSubdomainCount()))
                .replace("{parentDomain}", escapePlaceholder(record.getParentDomain()))
                .replace("{leftmostLabel}", escapePlaceholder(record.getLeftmostLabel()))
                .replace("{leftmostLabelLength}", String.valueOf(record.getLeftmostLabelLength()))
                .replace("{maxLabelLength}", String.valueOf(record.getMaxLabelLength()))
                .replace("{digitRatio}", formatDouble(record.getDigitRatio()))
                .replace("{hyphenRatio}", formatDouble(record.getHyphenRatio()))
                .replace("{uniqueCharacterRatio}", formatDouble(record.getUniqueCharacterRatio()))
                .replace("{base32Like}", String.valueOf(record.isBase32Like()))
                .replace("{base64Like}", String.valueOf(record.isBase64Like()))
                .replace("{hasPunycode}", String.valueOf(record.hasPunycode()))
                .replace("{hasIpLikeLabel}", String.valueOf(record.hasIpLikeLabel()))
                .replace("{hasSuspiciousKeyword}", String.valueOf(record.hasSuspiciousKeyword()));
    }

    @Override
    public void logAnomaly(DnsQueryRecord record, AnalysisResult result) {
        logger.info("DNS_ANOMALY_DETECTED client={} domain={} queryType={} confidence={} reason={} timestamp={}",
                record.getClientIp(), record.getDomain(), record.getQueryType(),
                result.confidence(), result.reason(), record.getTimestamp());
    }

    @Override
    public String getConfigPrefix() { return configPrefix; }

    private String escapePlaceholder(String value) {
        if (value == null) return "";
        return value.replace("{", "{{").replace("}", "}}");
    }

    private String formatDouble(double value) { return String.format("%.2f", value); }

    private String loadPromptTemplate(String resourceName) {
        try (var input = getClass().getClassLoader().getResourceAsStream(resourceName)) {
            if (input == null) {
                logger.warn("Prompt template not found: {}", resourceName);
                return "";
            }
            return new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Prompt template loading failed: {}", resourceName, e);
            return "";
        }
    }
}