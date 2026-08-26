package ru.galkov.loadtest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * HTTP Proxy Load Test with detailed statistics
 * <p>
 * Usage:
 * java -cp dpi.jar ru.galkov.loadtest.HttpProxyLoadTest
 * Or from Maven:
 * mvn exec:java -Dexec.mainClass="ru.galkov.loadtest.HttpProxyLoadTest"
 */
public class HttpProxyLoadTest {

    private static final Logger logger = LoggerFactory.getLogger(HttpProxyLoadTest.class);
    private static final DecimalFormat DF = new DecimalFormat("#,###.##");

    private static final String PROXY_HOST = "10.0.3.10";
    private static final int PROXY_PORT = 3128;
    private static final int TIMEOUT_MS = 10000;
    private static final int SLEEP_TIMEOUT = 3000;
    private static final int CLIENTS = 95;
    private static final int REQUESTS = 1000;

    // Список URL для тестирования (чтобы избежать блокировки за частые запросы к одному)
    private static final List<String> TEST_URLS = Arrays.asList(
            "https://www.wikipedia.org",          // Быстрый, без защиты
            "https://www.google.com",
            "https://www.github.com",
            "https://www.stackoverflow.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://www.yandex.ru",
            "https://www.rbc.ru",
            "https://www.linkedin.com",
            "https://www.amazon.com"
    );

    public static void main(String[] args) throws Exception {
        int concurrentClients = CLIENTS;
        int requestsPerClient;

        if (args.length >= 1) concurrentClients = Integer.parseInt(args[0]);
        if (args.length >= 2) requestsPerClient = Integer.parseInt(args[1]);
        else requestsPerClient = REQUESTS;


        logger.info("========================================");
        logger.info("       HTTP PROXY LOAD TEST");
        logger.info("========================================");
        logger.info("Target: {}:{}", PROXY_HOST, PROXY_PORT);
        logger.info("Test URLs: {} URLs", TEST_URLS.size());
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
        AtomicLong totalBytes = new AtomicLong(0);
        AtomicLong minLatencyNs = new AtomicLong(Long.MAX_VALUE);
        AtomicLong maxLatencyNs = new AtomicLong(0);

        // Детальная статистика по кодам ответов
        ConcurrentHashMap<Integer, AtomicLong> responseCodes = new ConcurrentHashMap<>();
        // Детальная статистика по ошибкам
        ConcurrentHashMap<String, AtomicLong> errorTypes = new ConcurrentHashMap<>();
        // Статистика по URL
        ConcurrentHashMap<String, RequestStats> urlStats = new ConcurrentHashMap<>();

        long startTime = System.nanoTime();

        for (int i = 0; i < concurrentClients; i++) {
            int clientId = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    Random random = new Random();

                    for (int j = 0; j < requestsPerClient; j++) {
                        if (j > 0) Thread.sleep(SLEEP_TIMEOUT);
                        // Выбираем случайный URL
                        String testUrl = TEST_URLS.get(random.nextInt(TEST_URLS.size()));
                        long requestStart = System.nanoTime();
                        HttpResult result = sendHttpRequest(testUrl);
                        long requestEnd = System.nanoTime();
                        long latencyNs = requestEnd - requestStart;

                        totalRequests.incrementAndGet();
                        totalLatencyNs.addAndGet(latencyNs);
                        totalBytes.addAndGet(result.bytesTransferred);

                        if (result.success) {
                            successfulRequests.incrementAndGet();
                        } else {
                            failedRequests.incrementAndGet();
                        }

                        // Статистика по кодам ответов
                        responseCodes.computeIfAbsent(result.responseCode, k -> new AtomicLong()).incrementAndGet();

                        // Статистика по ошибкам
                        if (result.errorType != null) {
                            errorTypes.computeIfAbsent(result.errorType, k -> new AtomicLong()).incrementAndGet();
                        }

                        // Статистика по URL
                        RequestStats stats = urlStats.computeIfAbsent(testUrl, k -> new RequestStats());
                        stats.totalRequests.incrementAndGet();
                        stats.totalLatencyNs.addAndGet(latencyNs);
                        if (result.success) stats.successfulRequests.incrementAndGet();
                        else stats.failedRequests.incrementAndGet();
                        stats.totalBytes.addAndGet(result.bytesTransferred);

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
        boolean completed = endLatch.await(120, TimeUnit.SECONDS);

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
        double throughputMbps = (totalBytes.get() / durationSeconds) / 1_048_576.0;

        // Print report
        logger.info("");
        logger.info("========================================");
        logger.info("           SUMMARY RESULTS");
        logger.info("========================================");
        logger.info("Total Requests:        {}", totalRequests.get());
        logger.info("Successful:            {}", successfulRequests.get());
        logger.info("Failed:                {}", failedRequests.get());
        logger.info("Data Transferred:      {} MB", DF.format(totalBytes.get() / 1_048_576.0));
        logger.info("Duration:              {} seconds", DF.format(durationSeconds));
        logger.info("----------------------------------------");
        logger.info("Throughput:            {} RPS", DF.format(rps));
        logger.info("Throughput:            {} MB/s", DF.format(throughputMbps));
        logger.info("Avg Latency:           {} ms", DF.format(avgLatencyMs));
        logger.info("Min Latency:           {} ms", DF.format(minLatencyMs));
        logger.info("Max Latency:           {} ms", DF.format(maxLatencyMs));
        logger.info("Error Rate:            {}%", DF.format(errorRate));
        logger.info("========================================");

        // Response codes breakdown
// Response codes breakdown
        logger.info("");
        logger.info("========================================");
        logger.info("         RESPONSE CODES");
        logger.info("========================================");
        responseCodes.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> {
                    long count = entry.getValue().get();
                    double percent = count * 100.0 / totalRequests.get();
                    logger.info("HTTP {}: {} ({}%)", entry.getKey(), DF.format(count), DF.format(percent));
                });
        logger.info("========================================");

// Error types breakdown
        if (!errorTypes.isEmpty()) {
            logger.info("");
            logger.info("========================================");
            logger.info("           ERROR TYPES");
            logger.info("========================================");
            errorTypes.entrySet().stream()
                    .sorted((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()))
                    .forEach(entry -> {
                        long count = entry.getValue().get();
                        double percent = count * 100.0 / totalRequests.get();
                        logger.info("{}: {} ({}%)", entry.getKey(), DF.format(count), DF.format(percent));
                    });
            logger.info("========================================");
        }

// Per-URL statistics
        logger.info("");
        logger.info("========================================");
        logger.info("         PER-URL STATISTICS");
        logger.info("========================================");
        urlStats.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue().totalRequests.get(), a.getValue().totalRequests.get()))
                .forEach(entry -> {
                    String url = entry.getKey();
                    RequestStats stats = entry.getValue();
                    double urlErrorRate = stats.totalRequests.get() > 0 ? stats.failedRequests.get() * 100.0 / stats.totalRequests.get() : 0;
                    double urlAvgLatency = stats.totalRequests.get() > 0 ? ((double) stats.totalLatencyNs.get() / stats.totalRequests.get()) / 1_000_000.0 : 0;
                    logger.info("{}:", url);
                    logger.info("  Requests: {} (Success: {}, Failed: {}, Error Rate: {}%)",
                            stats.totalRequests.get(), stats.successfulRequests.get(), stats.failedRequests.get(), DF.format(urlErrorRate));
                    logger.info("  Avg Latency: {} ms, Data: {} MB", DF.format(urlAvgLatency), DF.format(stats.totalBytes.get() / 1_048_576.0));
                });
        logger.info("========================================");

        if (!completed) {
            logger.error("Test timed out!");
        }
    }

    private static HttpResult sendHttpRequest(String testUrl) {
        String errorType = null;
        int responseCode = 0;
        long bytesTransferred = 0;
        boolean success = false;

        try {
            URL url = new URL(testUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection(
                    new Proxy(Proxy.Type.HTTP, new InetSocketAddress(PROXY_HOST, PROXY_PORT))
            );
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod("GET");
            conn.setInstanceFollowRedirects(true);

            // Добавляем User-Agent, чтобы не блокировали как бота
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            conn.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
            conn.setRequestProperty("Connection", "keep-alive");

            try (InputStream is = conn.getInputStream()) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    bytesTransferred += read;
                }
            }

            responseCode = conn.getResponseCode();

            // Считаем успехом 2xx и 3xx коды
            success = responseCode >= 200 && responseCode < 400;

            conn.disconnect();

        } catch (java.net.ConnectException e) {
            errorType = "ConnectException";
            responseCode = 0;
        } catch (java.net.SocketTimeoutException e) {
            errorType = "SocketTimeoutException";
            responseCode = 0;
        } catch (java.net.UnknownHostException e) {
            errorType = "UnknownHostException";
            responseCode = 0;
        } catch (java.io.IOException e) {
            errorType = "IOException";
            responseCode = 0;
        } catch (Exception e) {
            errorType = "Exception: " + e.getClass().getSimpleName();
            responseCode = 0;
        }

        return new HttpResult(success, responseCode, bytesTransferred, errorType);
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

    private static class HttpResult {
        final boolean success;
        final int responseCode;
        final long bytesTransferred;
        final String errorType;

        HttpResult(boolean success, int responseCode, long bytesTransferred, String errorType) {
            this.success = success;
            this.responseCode = responseCode;
            this.bytesTransferred = bytesTransferred;
            this.errorType = errorType;
        }
    }

    private static class RequestStats {
        final AtomicLong totalRequests = new AtomicLong(0);
        final AtomicLong successfulRequests = new AtomicLong(0);
        final AtomicLong failedRequests = new AtomicLong(0);
        final AtomicLong totalLatencyNs = new AtomicLong(0);
        final AtomicLong totalBytes = new AtomicLong(0);
    }
}