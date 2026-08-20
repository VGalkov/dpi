package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.util.Locale;
import java.util.concurrent.*;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class WorkerPool {
    private static final Logger logger = LoggerFactory.getLogger(WorkerPool.class);

    // ✅ П.27: Валидация size — при отсутствии/<=0 берём дефолт,
    //    вместо NPE/Invalid в static-ините
    private static final int POOL_SIZE =
            readPositiveInt("dns.thread.num", 4, "worker pool size");

    private static final int QUEUE_SIZE =
            readPositiveInt("worker-pool.queue-size", 100, "worker queue size");

    // ✅ П.60: Больше НЕ requireNonNull → нет ExceptionInInitializerError.
    //    Дефолт CALLER_RUNS
    private static final String REJECTION_POLICY =
            readRejectionPolicy("worker-pool.rejection-policy", "CALLER_RUNS");

    private static final ExecutorService POOL;
    private static final ArrayBlockingQueue<Runnable> taskQueue;

    static {
        taskQueue = new ArrayBlockingQueue<>(QUEUE_SIZE);

        RejectedExecutionHandler rejectionHandler = switch (REJECTION_POLICY.toUpperCase(Locale.ROOT)) {
            case "ABORT" -> new ThreadPoolExecutor.AbortPolicy();
            case "DISCARD" -> new ThreadPoolExecutor.DiscardPolicy();
            case "DISCARD_OLDEST" -> new ThreadPoolExecutor.DiscardOldestPolicy();
            default ->
                // ✅ П.58: НЕ выполняем в caller-потоке (иначе deadlock при
                //    заблокированном вызывающем). Отбрасываем + логируем.
                    (r, executor) -> {
                        logger.warn(LocaleUtil.getString("worker_pool_queue_full"),
                                taskQueue.size(), QUEUE_SIZE);
                        logger.warn("Task rejected due to full queue, discarding");
                    };
        };

        POOL = new ThreadPoolExecutor(
                POOL_SIZE,
                POOL_SIZE,
                0L,
                TimeUnit.MILLISECONDS,
                taskQueue,
                r -> {
                    Thread t = new Thread(r, "Worker-Pool-Thread");
                    t.setDaemon(true);
                    return t;
                },
                rejectionHandler
        );

        logger.info("WorkerPool initialized: poolSize={}, queueSize={}, rejectionPolicy={}",
                POOL_SIZE, QUEUE_SIZE, REJECTION_POLICY);
    }

    private WorkerPool() {}

    public static ExecutorService get() {
        return POOL;
    }

    public static Future<?> submit(Runnable task) {
        try {
            return POOL.submit(task);
        } catch (RejectedExecutionException e) {
            logger.warn("Task rejected: queue full ({}), rejection aborted", taskQueue.size());
            return null;
        }
    }

    public static <T> Future<T> submit(Callable<T> task) {
        try {
            return POOL.submit(task);
        } catch (RejectedExecutionException e) {
            logger.warn("Task rejected: queue full ({}), rejection aborted", taskQueue.size());
            return null;
        }
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
            logger.info(LocaleUtil.getString("worker_pool_shutdown_completed"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            POOL.shutdownNow();
            taskQueue.clear();
            logger.info(LocaleUtil.getString("worker_pool_shutdown_completed"));
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
            if (value == null || value.isBlank()) {
                return defaultVal;
            }
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