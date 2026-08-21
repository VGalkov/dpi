package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;
import ru.galkov.util.NamedThreadFactory;

import java.util.Locale;
import java.util.concurrent.*;
import java.util.concurrent.atomic.LongAdder;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class WorkerPool {
    private static final Logger logger = LoggerFactory.getLogger(WorkerPool.class);

    private static final int POOL_SIZE =
            readPositiveInt("dns.thread.num", 4, "worker pool size");

    private static final int QUEUE_SIZE =
            readPositiveInt("worker-pool.queue-size", 100, "worker queue size");

    private static final String REJECTION_POLICY =
            readRejectionPolicy("worker-pool.rejection-policy", "CALLER_RUNS");

    private static final ExecutorService POOL;
    private static final ArrayBlockingQueue<Runnable> taskQueue;
    private static final LongAdder rejectedTaskCounter = new LongAdder();

    static {
        taskQueue = new ArrayBlockingQueue<>(QUEUE_SIZE);

        RejectedExecutionHandler rejectionHandler = switch (REJECTION_POLICY.toUpperCase(Locale.ROOT)) {
            case "ABORT" -> new ThreadPoolExecutor.AbortPolicy();
            case "DISCARD" -> new ThreadPoolExecutor.DiscardPolicy();
            case "DISCARD_OLDEST" -> new ThreadPoolExecutor.DiscardOldestPolicy();
            default -> (r, executor) -> rejectedTaskCounter.increment();
        };

        POOL = new ThreadPoolExecutor(
                POOL_SIZE,
                POOL_SIZE,
                0L,
                TimeUnit.MILLISECONDS,
                taskQueue,
                new NamedThreadFactory("Worker-Pool-Thread", true),
                rejectionHandler
        );

        logger.info("WorkerPool initialized: poolSize={}, queueSize={}, rejectionPolicy={}",
                POOL_SIZE, QUEUE_SIZE, REJECTION_POLICY);
    }

    private WorkerPool() {}

    public static ExecutorService get() {
        return POOL;
    }

    public static void shutdown() {
        logger.info(LocaleUtil.getString("worker_pool_shutdown_initiated"));
        POOL.shutdown();
        taskQueue.clear();
        try {
            if (!POOL.awaitTermination(10, TimeUnit.SECONDS)) {
                logger.warn("WorkerPool did not terminate in time, forcing shutdown");
                POOL.shutdownNow();
                taskQueue.clear();
            }
            logRejectedTasks();
            logger.info(LocaleUtil.getString("worker_pool_shutdown_completed"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            POOL.shutdownNow();
            taskQueue.clear();
            logRejectedTasks();
            logger.info(LocaleUtil.getString("worker_pool_shutdown_completed"));
        }
    }

    private static void logRejectedTasks() {
        long rejected = rejectedTaskCounter.sumThenReset();
        if (rejected > 0) {
            logger.warn("WorkerPool rejected tasks: total={}, queueSize={}, queueCapacity={}",
                    rejected, taskQueue.size(), QUEUE_SIZE);
        }
    }

    private static int readPositiveInt(String key, int defaultVal, String what) {
        try {
            int value = getConfig().getInt(key);
            if (value > 0) return value;
            logger.warn("Invalid or missing {} ({}), using default {}", what, key, defaultVal);
            return defaultVal;
        } catch (Exception e) {
            logger.warn("Cannot read {} ({}), using default {}", what, key, defaultVal);
            return defaultVal;
        }
    }

    private static String readRejectionPolicy(String key, String defaultVal) {
        try {
            String value = getConfig().get(key);
            if (value.isBlank()) return defaultVal;
            String upper = value.toUpperCase(Locale.ROOT);
            return switch (upper) {
                case "ABORT", "DISCARD", "DISCARD_OLDEST", "CALLER_RUNS" -> upper;
                default -> {
                    logger.warn("Unknown rejection policy {}, using {}", value, defaultVal);
                    yield defaultVal;
                }
            };
        } catch (Exception e) {
            return defaultVal;
        }
    }
}