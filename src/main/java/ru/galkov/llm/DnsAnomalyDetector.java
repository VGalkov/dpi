package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;
import ru.galkov.util.LogFields;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class DnsAnomalyDetector extends AbstractAnomalyDetector<DnsQueryRecord> {
    private static final Logger logger = LoggerFactory.getLogger(DnsAnomalyDetector.class);

    // ✅ Оптимизация п.11: ConcurrentHashMap вместо LinkedBlockingQueue + removeIf
    private final ConcurrentHashMap<String, DnsQueryRecord> queue = new ConcurrentHashMap<>();
    private final Set<String> processingDomains = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> processedDomains = new ConcurrentHashMap<>();
    private final Map<String, Long> processedClients = new ConcurrentHashMap<>();

    public DnsAnomalyDetector() {
        super("dns.anomaly-detector");
    }

    @Override
    protected String getConfigPrefix() {
        return "dns_anomaly_detector";
    }

    @Override
    public void record(DnsQueryRecord record) {
        if (!enabled || !running || record == null || record.getDomain() == null || record.getClientIp() == null) return;

        // ✅ П.1: Убрана дублирующая проверка — только putIfAbsent
        DnsQueryRecord previousRecord = queue.putIfAbsent(record.getDomain(), record);

        if (previousRecord != null) {
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_duplicate_skipped"), record.getDomain(), record.getClientIp());
        } else {
            logger.debug(LocaleUtil.getString("dns_anomaly_detector_record_added"), record.getClientIp(), record.getDomain(), record.getQueryType());
        }
    }

    @Override
    protected void processQueue() {
        long lastCleanup = System.currentTimeMillis(), lastLlm = 0;
        while (running) {
            try {
                long now = System.currentTimeMillis();
                if (now - lastLlm < 120000) {
                    Thread.sleep(100);
                    continue;
                }
                if (now - lastCleanup > 10000) {
                    cleanupProcessed();
                    lastCleanup = now;
                }

                // ✅ Оптимизация: итерация по ConcurrentHashMap вместо poll
                for (Map.Entry<String, DnsQueryRecord> entry : queue.entrySet()) {
                    String domain = entry.getKey();

                    // Пропускаем если уже обрабатывается
                    if (processingDomains.contains(domain)) continue;

                    // Пропускаем если уже обработан
                    if (processedDomains.containsKey(domain)) {
                        queue.remove(domain);
                        continue;
                    }

                    // ✅ Оптимизация: атомарное извлечение из очереди
                    DnsQueryRecord record = queue.remove(domain);
                    if (record == null) continue;

                    // Помечаем как обрабатываемый
                    processingDomains.add(domain);

                    try {
                        long t = System.currentTimeMillis();
                        processedDomains.put(domain, t);
                        processedClients.put(record.getClientIp(), t);
                        AnalysisResult result = analyzeRecord(record);
                        lastLlm = System.currentTimeMillis();
                        if (result != null && result.suspicious() && result.confidence() >= trustThreshold) {
                            logger.info("{} {} {} {} {} {} {}", LogFields.kv("event", "DNS_ANOMALY_DETECTED"), LogFields.kv("client", record.getClientIp()),
                                    LogFields.kv("domain", domain), LogFields.kv("queryType", record.getQueryType()), LogFields.kv("confidence", result.confidence()),
                                    LogFields.kv("reason", result.reason()), LogFields.kv("timestamp", record.getTimestamp()));
                        }
                    } catch (Exception e) {
                        logger.error(LocaleUtil.getString("dns_anomaly_detector_processing_error"), e.getMessage());
                    } finally {
                        processingDomains.remove(domain);
                    }

                    // Ограничение частоты запросов к LLM
                    break;
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
        int rd = 0, rc = 0;
        for (Map.Entry<String, Long> e : processedDomains.entrySet()) {
            if (e.getValue() < expiry) {
                processedDomains.remove(e.getKey());
                rd++;
            }
        }
        for (Map.Entry<String, Long> e : processedClients.entrySet()) {
            if (e.getValue() < expiry) {
                processedClients.remove(e.getKey());
                rc++;
            }
        }
        if (rd > 0 || rc > 0) {
            logger.info(LocaleUtil.getString("dns_anomaly_detector_cleanup"), rd, rc, processedTtlMillis / 1000);
        }
    }

    private AnalysisResult analyzeRecord(DnsQueryRecord record) {
        String prompt = llmClient.loadPromptTemplate("prompts/dns_anomaly_prompt.txt")
                .replace("{clientIp}", record.getClientIp())
                .replace("{domain}", record.getDomain())
                .replace("{queryType}", String.valueOf(record.getQueryType()))
                .replace("{domainLength}", String.valueOf(record.getDomainLength()))
                .replace("{entropy}", String.format("%.2f", record.getEntropy()))
                .replace("{subdomainCount}", String.valueOf(record.getSubdomainCount()))
                .replace("{qr}", record.isQuery() ? "QUERY" : "RESPONSE")
                .replace("{opcode}", String.valueOf(record.getOpcode()))
                .replace("{tc}", record.isTruncated() ? "true" : "false")
                .replace("{rd}", record.isRecursionDesired() ? "true" : "false")
                .replace("{rcode}", String.valueOf(record.getRcode()));

        return analyzeWithLlm(prompt);
    }

    // ✅ Метод для обратной совместимости
    public void recordQuery(String clientIp, String domain, int queryType, boolean isQuery, int opcode, boolean isTruncated, boolean recursionDesired, int z, int rcode) {
        record(new DnsQueryRecord(clientIp, domain, queryType, System.currentTimeMillis(), isQuery, opcode, isTruncated, recursionDesired, z, rcode));
    }
}