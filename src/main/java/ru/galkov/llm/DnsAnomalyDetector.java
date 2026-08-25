package ru.galkov.llm;

import ru.galkov.util.LocaleUtil;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class DnsAnomalyDetector extends LlmAnomalyDetector<DnsQueryRecord> {
    private static final int DEFAULT_MAX_QUEUE_SIZE = 10000;
    private static final int DEFAULT_MAX_PROCESSED_DOMAINS = 100000;
    private static final int DEFAULT_MAX_PROCESSED_CLIENTS = 100000;
    private final int maxQueueSize;
    private final int maxProcessedDomains;
    private final int maxProcessedClients;
    private final long minLlmIntervalMillis;
    private final ConcurrentHashMap<String, DnsQueryRecord> queue = new ConcurrentHashMap<>();
    private final Set<String> processingDomains = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> processedDomains = new ConcurrentHashMap<>();
    private final Map<String, Long> processedClients = new ConcurrentHashMap<>();

    public DnsAnomalyDetector() {
        super(new DnsAnomalyStrategy("dns.anomaly-detector"), "dns.anomaly-detector");
        this.maxQueueSize = Math.max(1, getConfigInt("dns.anomaly-detector.max-queue-size", DEFAULT_MAX_QUEUE_SIZE));
        this.maxProcessedDomains = Math.max(1000, getConfigInt("dns.anomaly-detector.max-processed-domains", DEFAULT_MAX_PROCESSED_DOMAINS));
        this.maxProcessedClients = Math.max(1000, getConfigInt("dns.anomaly-detector.max-processed-clients", DEFAULT_MAX_PROCESSED_CLIENTS));
        this.minLlmIntervalMillis = Math.max(100, getConfigInt("dns.anomaly-detector.min-llm-interval-millis"));
    }

    @Override
    protected void processQueue() {
        long lastCleanup = System.currentTimeMillis(), lastLlm = 0;
        while (running) {
            try {
                long now = System.currentTimeMillis();
                if (now - lastLlm < minLlmIntervalMillis) { Thread.sleep(100); continue; }
                if (now - lastCleanup > 10000) { cleanupProcessed(); lastCleanup = now; }
                List<String> domainsToProcess = new ArrayList<>();
                for (Map.Entry<String, DnsQueryRecord> entry : queue.entrySet()) {
                    String domain = entry.getKey();
                    if (!processingDomains.contains(domain) && !processedDomains.containsKey(domain))
                        domainsToProcess.add(domain);
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
                        analyzeRecord(record);
                        lastLlm = System.currentTimeMillis();
                    } catch (Exception e) {
                        logger.error(LocaleUtil.getString("dns_anomaly_detector_processing_error"), e.getMessage());
                    } finally { processingDomains.remove(domain); }
                    processed++;
                }
                Thread.sleep(100);
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            catch (Exception e) { logger.error(LocaleUtil.getString("dns_anomaly_detector_processing_error"), e.getMessage()); }
        }
        logger.debug(LocaleUtil.getString("dns_anomaly_detector_queue_completed"));
    }

    @Override
    public void record(DnsQueryRecord record) {
        if (!enabled || !running || record == null || record.getDomain() == null || record.getClientIp() == null) return;
        if (isBlockedByBlacklist(record.getDomain(), record.getClientIp())) {
            logger.debug("Skipping blacklisted domain={} or clientIp={}", record.getDomain(), record.getClientIp());
            return;
        }
        if (queue.size() >= maxQueueSize) {
            logger.debug("DNS anomaly queue full (size={}), dropping record for domain={}", queue.size(), record.getDomain());
            return;
        }
        DnsQueryRecord previousRecord = queue.putIfAbsent(record.getDomain(), record);
        if (previousRecord != null) {
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_duplicate_skipped"), record.getDomain(), record.getClientIp());
        } else {
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_record_added"), record.getClientIp(), record.getDomain(), record.getQueryType());
        }
    }

    private void cleanupProcessed() {
        long expiry = System.currentTimeMillis() - processedTtlMillis;
        int removedDomains = 0, removedClients = 0;
        for (Map.Entry<String, Long> entry : processedDomains.entrySet()) if (entry.getValue() < expiry) removedDomains++;
        for (Map.Entry<String, Long> entry : processedClients.entrySet()) if (entry.getValue() < expiry) removedClients++;
        processedDomains.entrySet().removeIf(e -> e.getValue() < expiry);
        processedClients.entrySet().removeIf(e -> e.getValue() < expiry);
        trimToSize(processedDomains, maxProcessedDomains);
        trimToSize(processedClients, maxProcessedClients);
        if (removedDomains > 0 || removedClients > 0)
            logger.info("DNS cleanup: removed domains={}, clients={}, ttl={}s", removedDomains, removedClients, processedTtlMillis / 1000);
    }

    private void trimToSize(Map<String, Long> map, int maxSize) {
        int excess = map.size() - maxSize;
        if (excess <= 0) return;
        List<Map.Entry<String, Long>> eldest = new ArrayList<>(map.entrySet());
        eldest.sort(Comparator.comparingLong(Map.Entry::getValue));
        int toRemove = Math.min(excess, eldest.size());
        for (int i = 0; i < toRemove; i++) map.remove(eldest.get(i).getKey(), eldest.get(i).getValue());
    }

    public void recordQuery(String clientIp, String domain, int queryType, boolean isQuery,
                            int opcode, boolean isTruncated, boolean recursionDesired, int z, int rcode) {
        if (isBlockedByBlacklist(domain, clientIp)) {
            logger.debug("Skipping blacklisted domain={} or clientIp={}", domain, clientIp);
            return;
        }
        record(new DnsQueryRecord(clientIp, domain, queryType, System.currentTimeMillis(),
                isQuery, opcode, isTruncated, recursionDesired, z, rcode));
    }
}