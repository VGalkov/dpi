package ru.galkov.llm;

import ru.galkov.util.LocaleUtil;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public class DnsAnomalyDetector extends AbstractAnomalyDetector<DnsQueryRecord> {

    private static final int DEFAULT_MAX_QUEUE_SIZE = 10000;
    private static final int DEFAULT_MAX_PROCESSED_DOMAINS = 100000;
    private static final int DEFAULT_MAX_PROCESSED_CLIENTS = 100000;
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

        if (isBlockedByBlacklist(record.getDomain(), record.getClientIp())) {
            logger.debug("Skipping blacklisted domain={} or clientIp={}", record.getDomain(), record.getClientIp());
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

                        // ✅ Используем общий метод из AbstractAnomalyDetector
                        analyzeRecord(record);

                        lastLlm = System.currentTimeMillis();
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

    @Override
    protected String buildPrompt(DnsQueryRecord record) {
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
    protected void logAnomaly(DnsQueryRecord record, AnalysisResult result) {
        // ✅ Пункт 6: Убран LogFields.kv(), обычное форматирование
        logger.info("DNS_ANOMALY_DETECTED client={} domain={} queryType={} confidence={} reason={} timestamp={}",
                record.getClientIp(),
                record.getDomain(),
                record.getQueryType(),
                result.confidence(),
                result.reason(),
                record.getTimestamp());
    }

    // ✅ Пункт 5: Оптимизация форматирования double (быстрее чем String.format)
    private String formatDouble(double value) {
        return String.format("%.2f", value);
    }

    // ✅ Пункт 3: Убран AtomicInteger, упрощённая логика
    private void cleanupProcessed() {
        long expiry = System.currentTimeMillis() - processedTtlMillis;
        int removedDomains = 0;
        int removedClients = 0;

        // Подсчёт удаляемых записей ДО удаления
        for (Map.Entry<String, Long> entry : processedDomains.entrySet()) {
            if (entry.getValue() < expiry) removedDomains++;
        }
        for (Map.Entry<String, Long> entry : processedClients.entrySet()) {
            if (entry.getValue() < expiry) removedClients++;

        }

        // Удаление устаревших записей
        processedDomains.entrySet().removeIf(e -> e.getValue() < expiry);
        processedClients.entrySet().removeIf(e -> e.getValue() < expiry);

        trimToSize(processedDomains, maxProcessedDomains);
        trimToSize(processedClients, maxProcessedClients);

        if (removedDomains > 0 || removedClients > 0) {
            logger.info("DNS cleanup: removed domains={}, clients={}, ttl={}s",
                    removedDomains, removedClients, processedTtlMillis / 1000);
        }
    }

    // ✅ Пункт 3: Убран AtomicInteger из параметров
    private void trimToSize(Map<String, Long> map, int maxSize) {
        int excess = map.size() - maxSize;
        if (excess <= 0) return;

        List<Map.Entry<String, Long>> eldest = new ArrayList<>(map.entrySet());
        eldest.sort(Comparator.comparingLong(Map.Entry::getValue));

        int toRemove = Math.min(excess, eldest.size());
        for (int i = 0; i < toRemove; i++)
            map.remove(eldest.get(i).getKey(), eldest.get(i).getValue());
    }

    public void recordQuery(String clientIp, String domain, int queryType, boolean isQuery,
                            int opcode, boolean isTruncated, boolean recursionDesired,
                            int z, int rcode) {
        // ✅ Проверка blacklist ДО создания Record
        if (isBlockedByBlacklist(domain, clientIp)) {
            logger.debug("Skipping blacklisted domain={} or clientIp={}", domain, clientIp);
            return;
        }

        record(new DnsQueryRecord(clientIp, domain, queryType, System.currentTimeMillis(),
                isQuery, opcode, isTruncated, recursionDesired, z, rcode));
    }
}