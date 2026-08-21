package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;
import ru.galkov.util.LogFields;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class DnsAnomalyDetector extends AbstractAnomalyDetector<DnsQueryRecord> {
    private static final Logger logger = LoggerFactory.getLogger(DnsAnomalyDetector.class);

    private static final int DEFAULT_MAX_QUEUE_SIZE = 10000;
    private static final int DEFAULT_MAX_PROCESSED_DOMAINS = 100000;
    private static final int DEFAULT_MAX_PROCESSED_CLIENTS = 100000;
    private static final long DEFAULT_MIN_LLM_INTERVAL_MILLIS = 120000;

    private final int maxQueueSize;
    private final int maxProcessedDomains;
    private final int maxProcessedClients;
    private final long minLlmIntervalMillis;
    private final String promptTemplate;
    private final ConcurrentHashMap<String, DnsQueryRecord> queue = new ConcurrentHashMap<>();
    private final Set<String> processingDomains = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> processedDomains = new ConcurrentHashMap<>();
    private final Map<String, Long> processedClients = new ConcurrentHashMap<>();

    public DnsAnomalyDetector() {
        super("dns.anomaly-detector");

        this.maxQueueSize = Math.max(1,
                getConfigInt("dns.anomaly-detector.max-queue-size", DEFAULT_MAX_QUEUE_SIZE));

        this.maxProcessedDomains = Math.max(1000,
                getConfigInt("dns.anomaly-detector.max-processed-domains", DEFAULT_MAX_PROCESSED_DOMAINS));
        this.maxProcessedClients = Math.max(1000,
                getConfigInt("dns.anomaly-detector.max-processed-clients", DEFAULT_MAX_PROCESSED_CLIENTS));

        this.minLlmIntervalMillis = Math.max(100, getConfigInt("dns.anomaly-detector.min-llm-interval-millis"));

        this.promptTemplate = llmClient.loadPromptTemplate("prompts/dns_anomaly_prompt.txt");
    }

    @Override
    protected String getConfigPrefix() {
        return "dns.anomaly-detector";
    }

    @Override
    public void record(DnsQueryRecord record) {
        if (!enabled || !running || record == null || record.getDomain() == null || record.getClientIp() == null) {
            return;
        }

        if (queue.size() >= maxQueueSize) {
            logger.warn("DNS anomaly queue full (size={}), dropping record for domain={}",
                    queue.size(), record.getDomain());
            return;
        }

        DnsQueryRecord previousRecord = queue.putIfAbsent(record.getDomain(), record);

        if (previousRecord != null) {
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_duplicate_skipped"),
                    record.getDomain(), record.getClientIp());
        } else {
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_record_added"),
                    record.getClientIp(), record.getDomain(), record.getQueryType());
        }
    }

    @Override
    protected void processQueue() {
        long lastCleanup = System.currentTimeMillis(), lastLlm = 0;
        while (running) {
            try {
                long now = System.currentTimeMillis();
                if (now - lastLlm < minLlmIntervalMillis) {
                    Thread.sleep(100);
                    continue;
                }
                if (now - lastCleanup > 10000) {
                    cleanupProcessed();
                    lastCleanup = now;
                }

                List<String> domainsToProcess = new ArrayList<>();
                for (Map.Entry<String, DnsQueryRecord> entry : queue.entrySet()) {
                    String domain = entry.getKey();
                    if (!processingDomains.contains(domain) && !processedDomains.containsKey(domain)) {
                        domainsToProcess.add(domain);
                    }
                }

                int processed = 0;
                for (String domain : domainsToProcess) {
                    if (processed >= 10) break;

                    DnsQueryRecord record = queue.remove(domain);
                    if (record == null) continue;
                    processingDomains.add(domain);

                    try {
                        long t = System.currentTimeMillis();
                        processedDomains.put(domain, t);
                        processedClients.put(record.getClientIp(), t);
                        AnalysisResult result = analyzeRecord(record);
                        lastLlm = System.currentTimeMillis();
                        if (result != null && result.suspicious()
                                && result.confidence() >= trustThreshold) {
                            logger.info("{} {} {} {} {} {} {}",
                                    LogFields.kv("event", "DNS_ANOMALY_DETECTED"),
                                    LogFields.kv("client", record.getClientIp()),
                                    LogFields.kv("domain", domain),
                                    LogFields.kv("queryType", record.getQueryType()),
                                    LogFields.kv("confidence", result.confidence()),
                                    LogFields.kv("reason", result.reason()),
                                    LogFields.kv("timestamp", record.getTimestamp()));
                        }
                    } catch (Exception e) {
                        logger.error(LocaleUtil.getString("dns_anomaly_detector_processing_error"), e.getMessage());
                    } finally {
                        processingDomains.remove(domain);
                    }

                    processed++;
                }

                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error(LocaleUtil.getString("dns_anomaly_detector_processing_error"), e.getMessage());
            }
        }
        logger.info(LocaleUtil.getString("dns_anomaly_detector_queue_completed"));
    }

    private void cleanupProcessed() {
        long expiry = System.currentTimeMillis() - processedTtlMillis;

        AtomicInteger rd = new AtomicInteger();
        AtomicInteger rc = new AtomicInteger();

        processedDomains.entrySet().removeIf(e -> {
            if (e.getValue() < expiry) { rd.incrementAndGet(); return true; }
            return false;
        });
        processedClients.entrySet().removeIf(e -> {
            if (e.getValue() < expiry) { rc.incrementAndGet(); return true; }
            return false;
        });

        trimToSize(processedDomains, maxProcessedDomains, rd);
        trimToSize(processedClients, maxProcessedClients, rc);

        if (rd.get() > 0 || rc.get() > 0) {
            logger.info(LocaleUtil.getString("dns_anomaly_detector_cleanup"),
                    rd.get(), rc.get(), processedTtlMillis / 1000);
        }
    }

    private void trimToSize(Map<String, Long> map, int maxSize, AtomicInteger removedCounter) {
        int excess = map.size() - maxSize;
        if (excess <= 0) return;

        List<Map.Entry<String, Long>> eldest = new ArrayList<>(map.entrySet());
        eldest.sort(Comparator.comparingLong(Map.Entry::getValue));

        int toRemove = Math.min(excess, eldest.size());
        for (int i = 0; i < toRemove; i++) {
            if (map.remove(eldest.get(i).getKey(), eldest.get(i).getValue())) removedCounter.incrementAndGet();
        }
    }

    private AnalysisResult analyzeRecord(DnsQueryRecord record) {
        String prompt = promptTemplate
                .replace("{clientIp}", escapePlaceholder(record.getClientIp()))
                .replace("{domain}", escapePlaceholder(record.getDomain()))
                .replace("{queryType}", String.valueOf(record.getQueryType()))
                .replace("{timestamp}", String.valueOf(record.getTimestamp()))
                .replace("{qr}", record.isQuery() ? "QUERY" : "RESPONSE")
                .replace("{opcode}", String.valueOf(record.getOpcode()))
                .replace("{tc}", record.isTruncated() ? "true" : "false")
                .replace("{rd}", record.isRecursionDesired() ? "true" : "false")
                .replace("{z}", String.valueOf(record.getZ()))
                .replace("{rcode}", String.valueOf(record.getRcode()))
                .replace("{domainLength}", String.valueOf(record.getDomainLength()))
                .replace("{entropy}", String.format(Locale.ROOT, "%.2f", record.getEntropy()))
                .replace("{subdomainCount}", String.valueOf(record.getSubdomainCount()))
                .replace("{parentDomain}", escapePlaceholder(record.getParentDomain()))
                .replace("{leftmostLabel}", escapePlaceholder(record.getLeftmostLabel()))
                .replace("{leftmostLabelLength}", String.valueOf(record.getLeftmostLabelLength()))
                .replace("{maxLabelLength}", String.valueOf(record.getMaxLabelLength()))
                .replace("{digitRatio}", String.format(Locale.ROOT, "%.2f", record.getDigitRatio()))
                .replace("{hyphenRatio}", String.format(Locale.ROOT, "%.2f", record.getHyphenRatio()))
                .replace("{uniqueCharacterRatio}", String.format(Locale.ROOT, "%.2f", record.getUniqueCharacterRatio()))
                .replace("{base32Like}", String.valueOf(record.isBase32Like()))
                .replace("{base64Like}", String.valueOf(record.isBase64Like()))
                .replace("{hasPunycode}", String.valueOf(record.hasPunycode()))
                .replace("{hasIpLikeLabel}", String.valueOf(record.hasIpLikeLabel()))
                .replace("{hasSuspiciousKeyword}", String.valueOf(record.hasSuspiciousKeyword()));

        return analyzeWithLlm(prompt);
    }

    private String escapePlaceholder(String value) {
        if (value == null) return "";
        return value.replace("{", "{{").replace("}", "}}");
    }

    public void recordQuery(String clientIp, String domain, int queryType, boolean isQuery,
                            int opcode, boolean isTruncated, boolean recursionDesired,
                            int z, int rcode) {
        record(new DnsQueryRecord(clientIp, domain, queryType, System.currentTimeMillis(),
                isQuery, opcode, isTruncated, recursionDesired, z, rcode));
    }
}