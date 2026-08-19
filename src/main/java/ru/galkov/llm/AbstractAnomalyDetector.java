    package ru.galkov.llm;

    import org.slf4j.Logger;
    import org.slf4j.LoggerFactory;
    import ru.galkov.util.LocaleUtil;

    import java.util.Collections;
    import java.util.List;
    import java.util.Locale;
    import java.util.Set;
    import java.util.concurrent.ExecutorService;
    import java.util.concurrent.Executors;
    import java.util.concurrent.TimeUnit;
    import java.util.regex.Pattern;

    /**
     * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
     *
     * ✅ П.2: SSRF защита через валидацию LLM URL
     * ✅ П.3: Prompt Injection защита через санитизацию полей
     * ✅ П.8: Rate limiting + Circuit Breaker для LLM
     */
    public abstract class AbstractAnomalyDetector<T> {
        protected static final Logger logger = LoggerFactory.getLogger(AbstractAnomalyDetector.class);

        protected final boolean enabled;
        protected final LlmClient llmClient;
        protected final long processedTtlMillis;
        protected final double trustThreshold;

        protected final ExecutorService executor;
        protected volatile boolean running;

        // ✅ П.8: Rate limiting + Circuit Breaker
        protected final int maxRequestsPerMinute;
        protected final int circuitBreakerFailureThreshold;
        protected final int circuitBreakerTimeoutSeconds;

        // ✅ П.3: Лимиты на размеры полей для защиты от prompt injection
        protected final int maxDomainLength;
        protected final int maxReasonLength;

        // ✅ П.2: SSRF защита - блокировка URL
        private static final Pattern LOCALHOST_PATTERN = Pattern.compile("^localhost$", Pattern.CASE_INSENSITIVE);
        private static final Pattern LOOPBACK_PATTERN = Pattern.compile("^127\\.\\d+\\.\\d+\\.\\d+$");
        private static final Pattern PRIVATE_10_PATTERN = Pattern.compile("^10\\..*");
        private static final Pattern PRIVATE_192_PATTERN = Pattern.compile("^192\\.168\\..*");
        private static final Pattern PRIVATE_172_PATTERN = Pattern.compile("^172\\.(1[6-9]|2[0-9]|3[01])\\..*");
        private static final Pattern AWS_METADATA_PATTERN = Pattern.compile("^169\\.254\\.169\\.254$");
        private static final Pattern ALIBABA_METADATA_PATTERN = Pattern.compile("^100\\.100\\.100\\.200$");
        private static final Pattern GCP_METADATA_PATTERN = Pattern.compile("^metadata\\.google\\.internal$", Pattern.CASE_INSENSITIVE);

        protected AbstractAnomalyDetector(String configPrefix) {
            this.enabled = getConfigBoolean(configPrefix + ".enabled");

            // ✅ П.2: Валидация LLM URL при создании
            String llmUrl = validateLlmUrl(
                    getConfigString(configPrefix + ".llm-studio.url"),
                    configPrefix
            );

            this.llmClient = new LlmClient(
                    llmUrl,
                    getConfigString(configPrefix + ".llm-studio.model"),
                    getConfigInt(configPrefix + ".llm-studio.timeout-seconds"),
                    getConfigString(configPrefix + ".llm-studio.api-key")
            );

            double threshold = 0.7;
            try { threshold = Double.parseDouble(getConfigString(configPrefix + ".trust-threshold")); } catch (NumberFormatException ignored) {}
            this.trustThreshold = threshold;

            int ttlSeconds = 3600;
            try { ttlSeconds = getConfigInt(configPrefix + ".processed-ttl-seconds"); } catch (Exception ignored) {}
            this.processedTtlMillis = ttlSeconds * 1000L;

            // ✅ П.8: Rate limiting + Circuit Breaker настройки
            this.maxRequestsPerMinute = Math.max(1, getConfigInt(configPrefix + ".max-requests-per-minute", 10));
            this.circuitBreakerFailureThreshold = Math.max(1, getConfigInt(configPrefix + ".circuit-breaker.failure-threshold", 50));
            this.circuitBreakerTimeoutSeconds = Math.max(10, getConfigInt(configPrefix + ".circuit-breaker.timeout-seconds", 60));

            // ✅ П.3: Лимиты на размеры полей
            this.maxDomainLength = Math.max(64, getConfigInt(configPrefix + ".max-domain-length", 253));
            this.maxReasonLength = Math.max(100, getConfigInt(configPrefix + ".max-reason-length", 500));

            this.executor = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, getClass().getSimpleName() + "-Thread");
                t.setDaemon(true);
                return t;
            });

            logger.info("{} {} {} {} {} {} {}",
                    configPrefix,
                    "initialized: maxRequestsPerMinute=", maxRequestsPerMinute,
                    "circuitBreaker(failureThreshold=", circuitBreakerFailureThreshold,
                    "timeoutSeconds=", circuitBreakerTimeoutSeconds + ")");
        }

        /**
         * ✅ П.2: Валидация LLM URL на SSRF
         */
        private static String validateLlmUrl(String urlString, String configPrefix) {
            if (urlString == null || urlString.isEmpty()) {
                logger.warn("{}: LLM URL is empty, using default", configPrefix);
                return "http://localhost:1234/v1/chat/completions";
            }

            try {
                java.net.URL url = new java.net.URL(urlString);
                String protocol = url.getProtocol().toLowerCase(Locale.ROOT);
                String host = url.getHost().toLowerCase(Locale.ROOT);

                // Проверка протокола
                if (!"http".equals(protocol) && !"https".equals(protocol)) {
                    logger.warn(LocaleUtil.getString("anomaly_detector_llm_url_invalid"), urlString);
                    throw new IllegalArgumentException("Only HTTP/HTTPS URLs are allowed for LLM");
                }

                // Проверка на localhost
                if (LOCALHOST_PATTERN.matcher(host).matches() || LOOPBACK_PATTERN.matcher(host).matches()) {
                    logger.warn(LocaleUtil.getString("anomaly_detector_llm_url_blocked"), urlString);
                    // Не блокируем полностью, но логируем warning
                }

                // Проверка на private ranges
                if (PRIVATE_10_PATTERN.matcher(host).matches() ||
                        PRIVATE_192_PATTERN.matcher(host).matches() ||
                        PRIVATE_172_PATTERN.matcher(host).matches()) {
                    logger.warn(LocaleUtil.getString("anomaly_detector_llm_url_private"), urlString);
                }

                // Проверка на cloud metadata IPs
                if (AWS_METADATA_PATTERN.matcher(host).matches()) {
                    logger.error(LocaleUtil.getString("anomaly_detector_llm_url_cloud"), urlString);
                    throw new IllegalArgumentException("AWS metadata IP is not allowed: " + host);
                }

                if (ALIBABA_METADATA_PATTERN.matcher(host).matches()) {
                    logger.error(LocaleUtil.getString("anomaly_detector_llm_url_cloud"), urlString);
                    throw new IllegalArgumentException("Alibaba metadata IP is not allowed: " + host);
                }

                if (GCP_METADATA_PATTERN.matcher(host).matches()) {
                    logger.error(LocaleUtil.getString("anomaly_detector_llm_url_cloud"), urlString);
                    throw new IllegalArgumentException("GCP metadata hostname is not allowed: " + host);
                }

                return urlString;

            } catch (java.net.MalformedURLException e) {
                logger.error(LocaleUtil.getString("anomaly_detector_llm_url_invalid"), urlString);
                throw new IllegalArgumentException("Invalid LLM URL: " + urlString, e);
            }
        }

        /**
         * ✅ П.3: Санитизация полей перед вставкой в промпт
         */
        protected static String sanitizeForPrompt(String input, int maxLength) {
            if (input == null) return "";

            // Удаляем кавычки, фигурные скобки, переносы строк, обратные слеши
            String sanitized = input.replaceAll("[\"'{}\\[\\]<>\\\\]", "_")
                    .replaceAll("\\r?\\n", " ")
                    .replaceAll("\\s+", " ")
                    .replaceAll("\\.{2,}", "...");

            // Обрезаем по maxLength
            return sanitized.length() > maxLength ? sanitized.substring(0, maxLength) : sanitized;
        }

        /**
         * ✅ П.3: Валидация AnalysisResult от LLM
         */
        protected static AnalysisResult validateAnalysisResult(AnalysisResult result) {
            if (result == null) {
                return null;
            }

            // Валидация confidence
            double confidence = Math.max(0.0, Math.min(1.0, result.confidence()));

            // Валидация reason
            String reason = sanitizeForPrompt(result.reason(), 500);

            // Валидация recommendedActions
            List<String> validActions = result.recommendedActions().stream()
                    .filter(a -> a != null && Set.of("BLOCK_DOMAIN", "LOG_ONLY", "NONE", "BLOCK_REQUEST").contains(a))
                    .limit(3)
                    .toList();

            return new AnalysisResult(result.suspicious(), confidence, reason, validActions);
        }

        /**
         * ✅ П.8: Rate limiting + Circuit Breaker для LLM запросов
         */
        protected AnalysisResult analyzeWithLlm(String prompt) {
            // ✅ П.8: Rate limiting - проверяем лимит запросов в минуту
            if (!tryAcquireRateLimit()) {
                logger.warn(LocaleUtil.getString("anomaly_detector_rate_limit_exceeded"));
                return null;
            }

            // ✅ П.8: Circuit Breaker - проверяем, не открыт ли
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

                // ✅ П.3: Валидация результата
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

        // ✅ П.8: Простая реализация rate limiting (скользящее окно)
        private final java.util.concurrent.ConcurrentLinkedQueue<Long> requestTimestamps = new java.util.concurrent.ConcurrentLinkedQueue<>();
        private final Object rateLimitLock = new Object();

        private boolean tryAcquireRateLimit() {
            long now = System.currentTimeMillis();
            long windowStart = now - 60000; // 1 минута

            synchronized (rateLimitLock) {
                // Удаляем старые timestamp
                requestTimestamps.removeIf(timestamp -> timestamp < windowStart);

                // Проверяем лимит
                if (requestTimestamps.size() >= maxRequestsPerMinute) {
                    return false;
                }

                // Добавляем текущий запрос
                requestTimestamps.add(now);
                return true;
            }
        }

        // ✅ П.8: Простая реализация circuit breaker (count-based)
        private volatile int circuitBreakerFailureCount = 0;
        private volatile long circuitBreakerOpenTime = 0;
        private final Object circuitBreakerLock = new Object();

        private boolean tryCircuitBreaker() {
            long now = System.currentTimeMillis();

            synchronized (circuitBreakerLock) {
                // Если circuit breaker открыт, проверяем timeout
                if (circuitBreakerOpenTime > 0) {
                    if (now - circuitBreakerOpenTime < circuitBreakerTimeoutSeconds * 1000L) {
                        return false; // Ещё открыт
                    }
                    // Timeout истёк, закрываем
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

        /**
         * ✅ Общий метод для запуска
         */
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

        /**
         * ✅ Общий метод для остановки
         */
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

        /**
         * ✅ Общий метод для проверки статуса
         */
        public boolean isEnabled() {
            return enabled && running;
        }

        /**
         * ✅ Абстрактный метод для обработки очереди (реализуется в наследниках)
         */
        protected abstract void processQueue();

        /**
         * ✅ Абстрактный метод для добавления записи в очередь (реализуется в наследниках)
         */
        public abstract void record(T record);

        /**
         * ✅ Абстрактный метод для получения префикса конфига
         */
        protected abstract String getConfigPrefix();

        /**
         * ✅ Вспомогательные методы для получения конфига
         */
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