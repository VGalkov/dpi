package ru.galkov.util;

/**
 * Изолированный набор интеграционных тестов ТОЛЬКО для DNS компонента DPI Proxy.
 * ТРЕБОВАНИЯ К ОКРУЖЕНИЮ:
 * 1. Запущен DNS сервер на 127.0.0.1:53
 * 2. Запущен основной сервис (Main.main())
 * 3. Запуск через Maven: mvn test -Dtest=DpiProxyDnsIntegrationTest
 */
public class DpiDnsIntegrationTest {
/*
    private static final Logger logger = LoggerFactory.getLogger(DpiDnsIntegrationTest.class);
    private static final DecimalFormat DF = new DecimalFormat("#,###.##");

    // Конфигурация
    private static final String DNS_HOST = "127.0.0.1";
    private static final int DNS_PORT = 53;
    private static final int DNS_TIMEOUT_MS = 2500;

    @BeforeAll
    public static void beforeAll() {
        logger.info("===============================================================================");
        logger.info("   STARTING DNS INTEGRATION TESTS FOR DPI PROXY");
        logger.info("   Target: {}:{}", DNS_HOST, DNS_PORT);
        logger.info("   Output Mode: Detailed Metrics & Statistics");
        logger.info("===============================================================================");
    }

    @Test
    public void testDnsBasicResolve() throws Exception {
        String testName = "BASIC: Resolve google.com";
        logger.info("[RUNNING] {}", testName);

        long startTime = System.nanoTime();
        byte[] query = createDnsQuery("google.com");
        byte[] response = sendDnsRequest(query);
        long endTime = System.nanoTime();

        // Валидация ответа
        assertNotNull(response, "CRITICAL: DNS response is NULL. Server is unreachable or crashed.");
        assertTrue(response.length > 12, "CRITICAL: Response too small. Expected header + answer section.");

        int latencyMs = (int) ((endTime - startTime) / 1_000_000);

        logger.info("[PASS] {} | Status: OK | Response Size: {} bytes | Latency: {} ms",
                testName, response.length, latencyMs);

        printDetailedStats(testName, 1, 0, latencyMs, latencyMs);
    }

    @Test
    public void testDnsPerformanceSingleThread() throws Exception {
        String testName = "PERF: Single Threaded Load (100 requests)";
        logger.info("[RUNNING] {}", testName);

        int totalRequests = 100;
        long totalLatencyNs = 0;
        int successCount = 0;
        int errorCount = 0;
        List<Integer> latenciesMs = new ArrayList<>();

        for (int i = 0; i < totalRequests; i++) {
            long start = System.nanoTime();
            try {
                String domain = "perf-test-" + i + ".example.com";
                byte[] query = createDnsQuery(domain);
                byte[] resp = sendDnsRequest(query);

                if (resp != null && resp.length > 0) {
                    successCount++;
                    long latency = (System.nanoTime() - start) / 1_000_000;
                    totalLatencyNs += (System.nanoTime() - start);
                    latenciesMs.add((int) latency);
                } else {
                    errorCount++;
                    logger.warn("Request {} failed: Empty response", i);
                }
            } catch (Exception e) {
                errorCount++;
                logger.error("Request {} failed with exception: {}", i, e.getMessage());
            }
        }

        double avgLatencyMs = successCount > 0 ? (totalLatencyNs / successCount / 1_000_000.0) : 0;
        double durationSec = totalLatencyNs / 1_000_000_000.0;
        double rps = durationSec > 0 ? (successCount / durationSec) : 0;

        logger.info("[RESULT] {} | Total: {}, Success: {}, Errors: {}",
                testName, totalRequests, successCount, errorCount);
        logger.info("[METRICS] Avg Latency: {} ms | Min Latency: {} ms | Max Latency: {} ms",
                DF.format(avgLatencyMs),
                latenciesMs.isEmpty() ? 0 : latenciesMs.stream().min(Integer::compare).get(),
                latenciesMs.isEmpty() ? 0 : latenciesMs.stream().max(Integer::compare).get());
        logger.info("[THROUGHPUT] Duration: {} s | RPS: {}", DF.format(durationSec), DF.format(rps));

        assertTrue(successCount > 0, "CRITICAL: No successful DNS responses received.");
        assertTrue(avgLatencyMs < 150, "WARNING: Average latency exceeded threshold (150ms). Current: " + avgLatencyMs);

        printDetailedStats(testName, successCount, errorCount, (int) avgLatencyMs, (int) (totalLatencyNs / 1_000_000));
    }

    @Test
    public void testDnsConcurrentLoad() throws Exception {
        String testName = "CONCURRENT: 50 Clients x 20 Requests";
        logger.info("[RUNNING] {}", testName);

        int clients = 50;
        int requestsPerClient = 70;
        ExecutorService executor = Executors.newFixedThreadPool(clients);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(clients);

        var successCount = new java.util.concurrent.atomic.AtomicInteger(0);
        var errorCount = new java.util.concurrent.atomic.AtomicInteger(0);
        var totalLatencyNs = new java.util.concurrent.atomic.LongAdder();
        var minLatency = new java.util.concurrent.atomic.AtomicLong(Long.MAX_VALUE);
        var maxLatency = new java.util.concurrent.atomic.AtomicLong(0);

        for (int c = 0; c < clients; c++) {
            int clientId = c;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int r = 0; r < requestsPerClient; r++) {
                        long start = System.nanoTime();
                        try {
                            String domain = "client-" + clientId + "-req-" + r + ".concurrent.test";
                            byte[] q = createDnsQuery(domain);
                            sendDnsRequest(q); // Ответ игнорируем, важна скорость и отсутствие краша

                            long latency = System.nanoTime() - start;
                            successCount.incrementAndGet();
                            totalLatencyNs.add(latency);

                            if (latency < minLatency.get()) minLatency.compareAndSet(minLatency.get(), latency);
                            if (latency > maxLatency.get()) maxLatency.compareAndSet(maxLatency.get(), latency);
                        } catch (Exception e) {
                            errorCount.incrementAndGet();
                            logger.debug("Client {} Req {} failed: {}", clientId, r, e.getMessage());
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    errorCount.incrementAndGet();
                } finally {
                    endLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        endLatch.await(20, TimeUnit.SECONDS);
        executor.shutdown();

        int totalSuccess = successCount.get();
        int totalErrors = errorCount.get();
        long totalDurationNs = totalLatencyNs.sum();
        int totalOps = totalSuccess + totalErrors;

        double avgLatencyMs = totalSuccess > 0 ? (totalDurationNs / totalSuccess / 1_000_000.0) : 0;
        double totalTimeSec = totalDurationNs / 1_000_000_000.0; // Грубая оценка времени работы
        double rps = totalTimeSec > 0 ? (totalOps / totalTimeSec) : 0;
        double errorRate = totalOps > 0 ? ((double) totalErrors / totalOps * 100) : 0;

        logger.info("[CONCURRENT RESULT] Total Ops: {}, Success: {}, Errors: {}", totalOps, totalSuccess, totalErrors);
        logger.info("[LATENCY STATS] Avg: {} ms | Min: {} ms | Max: {} ms",
                DF.format(avgLatencyMs),
                minLatency.get() / 1_000_000,
                maxLatency.get() / 1_000_000);
        logger.info("[SYSTEM STATS] Throughput: {} RPS | Error Rate: {}%",
                DF.format(rps), DF.format(errorRate));

        assertTrue(errorRate < 15.0, "CRITICAL: Concurrent error rate too high (" + errorRate + "%)");
        assertTrue(avgLatencyMs < 200, "CRITICAL: Average latency under load too high (" + avgLatencyMs + "ms)");

        printDetailedStats(testName, totalSuccess, totalErrors, (int) avgLatencyMs, (int) (totalDurationNs / 1_000_000));
    }


    private void printDetailedStats(String testName, int success, int errors, int avgLatency, int totalTimeMs) {
        logger.info("");
        logger.info("=== DETAILED STATISTICS REPORT: {} ===", testName);
        logger.info("| Metric                | Value          |");
        logger.info("|-----------------------|----------------|");
        logger.info("| Status                | {}             |", errors == 0 ? "PASSED" : "FAILED");
        logger.info("| Success Count         | {}             |", success);
        logger.info("| Error Count           | {}             |", errors);
        logger.info("| Avg Latency           | {} ms          |", avgLatency);
        logger.info("| Total Time            | {} ms          |", totalTimeMs);
        if (success > 0) {
            logger.info("| Efficiency            | {} req/sec     |", (success * 1000) / (totalTimeMs == 0 ? 1 : totalTimeMs));
        }
        logger.info("========================================\n");
    }


    private byte[] createDnsQuery(String domain) {
        byte[] buffer = new byte[512];
        int offset = 0;

        // ID (2 bytes) - случайный
        buffer[offset++] = (byte) (Math.random() * 255);
        buffer[offset++] = (byte) (Math.random() * 255);

        // Flags: Standard Query (0x0100)
        buffer[offset++] = 0x01;
        buffer[offset++] = 0x00;

        // QDCOUNT: 1 question
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x01;

        // ANCOUNT, NSCOUNT, ARCOUNT: 0
        for (int i = 0; i < 6; i++) buffer[offset++] = 0x00;

        // Question Section
        String[] parts = domain.split("\\.");
        for (String part : parts) {
            if (part.length() > 0 && part.length() <= 63) {
                buffer[offset++] = (byte) part.length();
                for (char c : part.toCharArray()) {
                    buffer[offset++] = (byte) c;
                }
            }
        }
        buffer[offset++] = 0x00; // End of name

        // QTYPE: A (1)
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x01;

        // QCLASS: IN (1)
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x01;

        return java.util.Arrays.copyOf(buffer, offset);
    }


    private byte[] sendDnsRequest(byte[] query) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(DNS_TIMEOUT_MS);
            InetAddress address = InetAddress.getByName(DNS_HOST);

            DatagramPacket sendPacket = new DatagramPacket(query, query.length, address, DNS_PORT);
            socket.send(sendPacket);

            byte[] receiveBuffer = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            socket.receive(receivePacket);

            return java.util.Arrays.copyOf(receiveBuffer, receivePacket.getLength());
        }
    }
    */
}
