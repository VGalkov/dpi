package ru.galkov.loadtest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * DNS Load Test
 * Usage:
 *   java -cp dpi.jar ru.galkov.loadtest.DnsLoadTest
 * Or from Maven:
 *   mvn exec:java -Dexec.mainClass="ru.galkov.loadtest.DnsLoadTest"
 */
public class DnsLoadTest {

    private static final Logger logger = LoggerFactory.getLogger(DnsLoadTest.class);
    private static final DecimalFormat DF = new DecimalFormat("#,###.##");
    private static final String DNS_HOST = "10.0.1.235";
    private static final int DNS_PORT = 53;
    private static final int TIMEOUT_MS = 3000;
    private static final int CLIENTS = 100;
    private static final int REQUESTS = 30;

    public static void main(String[] args) throws Exception {
        int concurrentClients = CLIENTS;
        int requestsPerClient;

        if (args.length >= 1) concurrentClients = Integer.parseInt(args[0]);
        if (args.length >= 2) requestsPerClient = Integer.parseInt(args[1]);
        else requestsPerClient = REQUESTS;

        logger.info("========================================");
        logger.info("         DNS LOAD TEST");
        logger.info("========================================");
        logger.info("Target: {}:{}", DNS_HOST, DNS_PORT);
        logger.info("Concurrent clients: {}", concurrentClients);
        logger.info("Requests per client: {}", requestsPerClient);
        logger.info("Total requests: {}", concurrentClients * requestsPerClient);
        logger.info("========================================");

        ExecutorService executor = Executors.newFixedThreadPool(concurrentClients);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(concurrentClients);

        AtomicLong totalRequests = new AtomicLong(0);
        AtomicLong successfulRequests = new AtomicLong(0);
        AtomicLong failedRequests = new AtomicLong(0);
        AtomicLong totalLatencyNs = new AtomicLong(0);
        AtomicLong minLatencyNs = new AtomicLong(Long.MAX_VALUE);
        AtomicLong maxLatencyNs = new AtomicLong(0);

        long startTime = System.nanoTime();

        for (int i = 0; i < concurrentClients; i++) {
            int clientId = i;
            executor.submit(() -> {
                try {
                    startLatch.await();

                    for (int j = 0; j < requestsPerClient; j++) {
                        long requestStart = System.nanoTime();
                        boolean success = sendDnsRequest("test" + clientId + "-" + j + ".example.com");
                        long requestEnd = System.nanoTime();
                        long latencyNs = requestEnd - requestStart;
                        totalRequests.incrementAndGet();
                        totalLatencyNs.addAndGet(latencyNs);
                        if (success) successfulRequests.incrementAndGet();
                        else failedRequests.incrementAndGet();
                        updateMin(minLatencyNs, latencyNs);
                        updateMax(maxLatencyNs, latencyNs);
                    }
                } catch (Exception e) {
                    logger.error("Client {} error: {}", clientId, e.getMessage());
                } finally {
                    endLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = endLatch.await(60, TimeUnit.SECONDS);

        long endTime = System.nanoTime();
        double durationSeconds = (endTime - startTime) / 1_000_000_000.0;

        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);

        // Calculate metrics
        long rps = (long) (totalRequests.get() / durationSeconds);
        double avgLatencyMs = (totalRequests.get() > 0) ? ((double) totalLatencyNs.get() / totalRequests.get()) / 1_000_000.0 : 0;
        double minLatencyMs = minLatencyNs.get() / 1_000_000.0;
        double maxLatencyMs = maxLatencyNs.get() / 1_000_000.0;
        double errorRate = (totalRequests.get() > 0) ? (failedRequests.get() * 100.0 / totalRequests.get()) : 0;

        // Print report
        logger.info("");
        logger.info("========================================");
        logger.info("              RESULTS");
        logger.info("========================================");
        logger.info("Total Requests:        {}", totalRequests.get());
        logger.info("Successful:            {}", successfulRequests.get());
        logger.info("Failed:                {}", failedRequests.get());
        logger.info("Duration:              {} seconds", DF.format(durationSeconds));
        logger.info("----------------------------------------");
        logger.info("Throughput:            {} RPS", DF.format(rps));
        logger.info("Avg Latency:           {} ms", DF.format(avgLatencyMs));
        logger.info("Min Latency:           {} ms", DF.format(minLatencyMs));
        logger.info("Max Latency:           {} ms", DF.format(maxLatencyMs));
        logger.info("Error Rate:            {}%", DF.format(errorRate));
        logger.info("========================================");

        if (!completed) logger.error("Test timed out!");
    }

    private static boolean sendDnsRequest(String domain) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(TIMEOUT_MS);
            socket.connect(new InetSocketAddress(DNS_HOST, DNS_PORT));

            byte[] query = createDnsQuery(domain);
            DatagramPacket packet = new DatagramPacket(query, query.length);
            socket.send(packet);

            byte[] response = new byte[512];
            DatagramPacket responsePacket = new DatagramPacket(response, response.length);
            socket.receive(responsePacket);

            return responsePacket.getLength() > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] createDnsQuery(String domain) {
        byte[] query = new byte[512];
        int pos = 0;

        // Transaction ID
        query[pos++] = 0x12;
        query[pos++] = 0x34;

        // Flags (standard query)
        query[pos++] = 0x01;
        query[pos++] = 0x00;

        // Questions: 1
        query[pos++] = 0x00;
        query[pos++] = 0x01;

        // Answer RRs: 0
        query[pos++] = 0x00;
        query[pos++] = 0x00;

        // Authority RRs: 0
        query[pos++] = 0x00;
        query[pos++] = 0x00;

        // Additional RRs: 0
        query[pos++] = 0x00;
        query[pos++] = 0x00;

        // Query domain
        for (String part : domain.split("\\.")) {
            query[pos++] = (byte) part.length();
            for (char c : part.toCharArray()) query[pos++] = (byte) c;
        }
        query[pos++] = 0x00;

        // Query type: A (1)
        query[pos++] = 0x00;
        query[pos++] = 0x01;

        // Query class: IN (1)
        query[pos++] = 0x00;
        query[pos++] = 0x01;

        return Arrays.copyOf(query, pos);
    }

    private static void updateMin(AtomicLong currentMin, long value) {
        long oldMin;
        do {
            oldMin = currentMin.get();
            if (value >= oldMin) break;
        } while (!currentMin.compareAndSet(oldMin, value));
    }

    private static void updateMax(AtomicLong currentMax, long value) {
        long oldMax;
        do {
            oldMax = currentMax.get();
            if (value <= oldMax) break;
        } while (!currentMax.compareAndSet(oldMax, value));
    }
}