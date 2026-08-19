package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public abstract class AbstractAnomalyDetector<T> {
    protected static final Logger logger = LoggerFactory.getLogger(AbstractAnomalyDetector.class);

    protected final boolean enabled;
    protected final LlmClient llmClient;
    protected final long processedTtlMillis;
    protected final double trustThreshold;

    protected final ExecutorService executor;
    protected volatile boolean running;

    protected final int maxRequestsPerMinute;
    protected final int circuitBreakerFailureThreshold;
    protected final int circuitBreakerTimeoutSeconds;

    protected final int maxDomainLength;
    protected final int maxReasonLength;

    private final java.util.concurrent.ConcurrentLinkedQueue<Long> requestTimestamps = new java.util.concurrent.ConcurrentLinkedQueue<>();
    private final Object rateLimitLock = new Object();

    private volatile int circuitBreakerFailureCount = 0;
    private volatile long circuitBreakerOpenTime = 0;
    private final Object circuitBreakerLock = new Object();

    protected AbstractAnomalyDetector(String configPrefix) {
        this.enabled = getConfigBoolean(configPrefix + ".enabled");

        String llmUrl = validateLlmUrl(
                getConfigString(configPrefix + ".llm-studio.url"),
                configPrefix
        );

        String model = getConfigString(configPrefix + ".llm-studio.model");
        if (model == null || model.isBlank()) {
            throw new IllegalArgumentException(configPrefix + ": LLM model must be configured");
        }

        int timeoutSeconds;
        try {
            timeoutSeconds = getConfigInt(configPrefix + ".llm-studio.timeout-seconds");
            if (timeoutSeconds <= 0) {
                throw new IllegalArgumentException(configPrefix + ": timeout-seconds must be positive");
            }
        } catch (Exception e) {
            timeoutSeconds = 30;
        }

        String apiKey = getConfigString(configPrefix + ".llm-studio.api-key");

        this.llmClient = new LlmClient(llmUrl, model, timeoutSeconds, apiKey);

        double threshold = 0.7;
        try {
            String thresholdStr = getConfigString(configPrefix + ".trust-threshold");
            if (thresholdStr != null && !thresholdStr.isBlank()) {
                threshold = Double.parseDouble(thresholdStr);
                if (!Double.isFinite(threshold) || threshold < 0.0 || threshold > 1.0) {
                    throw new IllegalArgumentException("trust-threshold must be between 0 and 1");
                }
            }
        } catch (RuntimeException e) {
            logger.warn("{}: invalid trust threshold, using default 0.7", configPrefix, e);
        }
        this.trustThreshold = threshold;

        int ttlSeconds = 3600;
        try {
            ttlSeconds = getConfigInt(configPrefix + ".processed-ttl-seconds");
            if (ttlSeconds <= 0) {
                ttlSeconds = 3600;
            }
        } catch (Exception e) {
            ttlSeconds = 3600;
        }
        this.processedTtlMillis = ttlSeconds * 1000L;

        this.maxRequestsPerMinute = Math.max(1, getConfigInt(configPrefix + ".max-requests-per-minute", 10));
        this.circuitBreakerFailureThreshold = Math.max(1, getConfigInt(configPrefix + ".circuit-breaker.failure-threshold", 50));
        this.circuitBreakerTimeoutSeconds = Math.max(10, getConfigInt(configPrefix + ".circuit-breaker.timeout-seconds", 60));

        this.maxDomainLength = Math.max(64, getConfigInt(configPrefix + ".max-domain-length", 253));
        this.maxReasonLength = Math.max(100, getConfigInt(configPrefix + ".max-reason-length", 500));

        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, getClass().getSimpleName() + "-Thread");
            t.setDaemon(true);
            return t;
        });

        logger.info("{} initialized: maxRequestsPerMinute={}, circuitBreaker(failureThreshold={}, timeoutSeconds={})",
                configPrefix, maxRequestsPerMinute, circuitBreakerFailureThreshold, circuitBreakerTimeoutSeconds);
    }

    private static String validateLlmUrl(String urlString, String configPrefix) {
        if (urlString == null || urlString.isBlank()) {
            throw new IllegalArgumentException(configPrefix + ": LLM URL must be configured");
        }

        try {
            URI uri = URI.create(urlString);

            String scheme = uri.getScheme();
            String host = uri.getHost();

            if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
                throw new IllegalArgumentException("Only HTTP and HTTPS schemes are allowed");
            }

            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("LLM URL host is missing");
            }

            if (uri.getUserInfo() != null) {
                throw new IllegalArgumentException("User info in LLM URL is not allowed");
            }

            if (uri.getFragment() != null) {
                throw new IllegalArgumentException("Fragment in LLM URL is not allowed");
            }

            int port = uri.getPort();
            if (port != -1 && (port < 1 || port > 65535)) {
                throw new IllegalArgumentException("Invalid LLM URL port");
            }

            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isBlockedAddress(address)) {
                    throw new IllegalArgumentException(
                            "LLM URL resolves to blocked address: " + address.getHostAddress());
                }
            }

            return uri.toString();

        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid or unresolved LLM URL", e);
        }
    }

    private static boolean isBlockedAddress(InetAddress address) {
        return address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()
                || isMetadataAddress(address)
                || isCgnatAddress(address);
    }

    private static boolean isMetadataAddress(InetAddress address) {
        byte[] bytes = address.getAddress();

        if (bytes.length == 4) {
            int a = bytes[0] & 0xff;
            int b = bytes[1] & 0xff;
            int c = bytes[2] & 0xff;
            int d = bytes[3] & 0xff;

            return (a == 169 && b == 254 && c == 169 && d == 254)
                    || (a == 100 && b == 100 && c == 100 && d == 200);
        }

        return address.getHostName().equalsIgnoreCase("metadata.google.internal");
    }

    private static boolean isCgnatAddress(InetAddress address) {
        byte[] bytes = address.getAddress();

        if (bytes.length != 4) {
            return false;
        }

        int first = bytes[0] & 0xff;
        int second = bytes[1] & 0xff;

        return first == 100 && second >= 64 && second <= 127;
    }

    protected static String sanitizeForPrompt(String input, int maxLength) {
        if (input == null || maxLength <= 0) {
            return "";
        }

        String bounded = input.length() > maxLength ? input.substring(0, maxLength) : input;

        return bounded
                .replaceAll("[\"'{}\\[\\]<>\\\\]", "_")
                .replaceAll("\\r?\\n", " ")
                .replaceAll("\\s+", " ")
                .replaceAll("\\.{2,}", "...");
    }

    protected static AnalysisResult validateAnalysisResult(AnalysisResult result) {
        if (result == null) {
            return null;
        }

        double confidence = result.confidence();
        if (!Double.isFinite(confidence)) {
            confidence = 0.0;
        }
        confidence = Math.max(0.0, Math.min(1.0, confidence));

        String reason = sanitizeForPrompt(result.reason(), 500);

        List<String> actions = result.recommendedActions() == null
                ? Collections.emptyList()
                : result.recommendedActions();

        List<String> validActions = actions.stream()
                .filter(a -> a != null)
                .map(String::trim)
                .filter(a -> Set.of("BLOCK_DOMAIN", "LOG_ONLY", "NONE", "BLOCK_REQUEST").contains(a))
                .limit(3)
                .toList();

        return new AnalysisResult(result.suspicious(), confidence, reason, validActions);
    }

    protected AnalysisResult analyzeWithLlm(String prompt) {
        if (!tryAcquireRateLimit()) {
            logger.warn(LocaleUtil.getString("anomaly_detector_rate_limit_exceeded"));
            return null;
        }

        if (!tryCircuitBreaker()) {
            logger.warn(LocaleUtil.getString("anomaly_detector_circuit_breaker_open"));
            return null;
        }

        try {
            String response = llmClient.sendRequest(prompt);
            if (response == null || response.isEmpty()) {
                logger.warn(LocaleUtil.getString(getConfigPrefix() + "_empty_response"));
                recordCircuitBreakerFailure();
                return null;
            }

            AnalysisResult result = llmClient.parseResponse(response);

            if (result != null) {
                result = validateAnalysisResult(result);
                recordCircuitBreakerSuccess();
            } else {
                recordCircuitBreakerFailure();
            }

            return result;

        } catch (Exception e) {
            logger.error(LocaleUtil.getString(getConfigPrefix() + "_analysis_error"), e.getMessage(), e);
            recordCircuitBreakerFailure();
            return null;
        }
    }

    private boolean tryAcquireRateLimit() {
        long now = System.currentTimeMillis();
        long windowStart = now - 60000;

        synchronized (rateLimitLock) {
            requestTimestamps.removeIf(timestamp -> timestamp < windowStart);

            if (requestTimestamps.size() >= maxRequestsPerMinute) {
                return false;
            }

            requestTimestamps.add(now);
            return true;
        }
    }

    private boolean tryCircuitBreaker() {
        long now = System.currentTimeMillis();

        synchronized (circuitBreakerLock) {
            if (circuitBreakerOpenTime > 0) {
                if (now - circuitBreakerOpenTime < circuitBreakerTimeoutSeconds * 1000L) {
                    return false;
                }
                circuitBreakerOpenTime = 0;
                circuitBreakerFailureCount = 0;
                logger.info("Circuit breaker closed after timeout");
            }

            return true;
        }
    }

    private void recordCircuitBreakerSuccess() {
        synchronized (circuitBreakerLock) {
            circuitBreakerFailureCount = 0;
        }
    }

    private void recordCircuitBreakerFailure() {
        synchronized (circuitBreakerLock) {
            circuitBreakerFailureCount++;

            if (circuitBreakerFailureCount >= circuitBreakerFailureThreshold) {
                circuitBreakerOpenTime = System.currentTimeMillis();
                logger.warn("Circuit breaker opened after {} failures", circuitBreakerFailureCount);
            }
        }
    }

    public void start() {
        if (!enabled) {
            logger.info(LocaleUtil.getString(getConfigPrefix() + "_disabled"));
            return;
        }
        if (running) {
            logger.warn(LocaleUtil.getString(getConfigPrefix() + "_already_running"));
            return;
        }
        running = true;
        executor.submit(this::processQueue);
        logger.info(LocaleUtil.getString(getConfigPrefix() + "_started"), getConfigString(getConfigPrefix().replace("_", ".") + ".llm-studio.model"));
    }

    public void stop() {
        if (!running) return;
        running = false;
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
        logger.info(LocaleUtil.getString(getConfigPrefix() + "_stopped"));
    }

    public boolean isEnabled() {
        return enabled && running;
    }

    protected abstract void processQueue();

    public abstract void record(T record);

    protected abstract String getConfigPrefix();

    protected static String getConfigString(String key) {
        try {
            return ru.galkov.Main.getConfig().get(key);
        } catch (Exception e) {
            return "";
        }
    }

    protected static int getConfigInt(String key) {
        try {
            return ru.galkov.Main.getConfig().getInt(key);
        } catch (Exception e) {
            return 0;
        }
    }

    protected static int getConfigInt(String key, int defaultValue) {
        try {
            return ru.galkov.Main.getConfig().getInt(key);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    protected static boolean getConfigBoolean(String key) {
        try {
            return ru.galkov.Main.getConfig().getBoolean(key);
        } catch (Exception e) {
            return false;
        }
    }
}