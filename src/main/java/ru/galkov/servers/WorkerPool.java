package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;
import ru.galkov.util.NamedThreadFactory;

import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
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

    private static final ArrayBlockingQueue<Runnable> TASK_QUEUE =
            new ArrayBlockingQueue<>(QUEUE_SIZE);

    private static final LongAdder REJECTED_TASK_COUNTER =
            new LongAdder();

    private static final AtomicBoolean SHUTDOWN_STARTED =
            new AtomicBoolean();

    private static final ThreadPoolExecutor POOL =
            createPool();

    private WorkerPool() {
    }

    private static ThreadPoolExecutor createPool() {
        return new ThreadPoolExecutor(
                POOL_SIZE,
                POOL_SIZE,
                0L,
                TimeUnit.MILLISECONDS,
                TASK_QUEUE,
                new NamedThreadFactory(
                        "Worker-Pool-Thread",
                        true
                ),
                createRejectionHandler()
        );
    }

    private static RejectedExecutionHandler createRejectionHandler() {
        return switch (REJECTION_POLICY) {
            case "ABORT" -> new ThreadPoolExecutor.AbortPolicy();
            case "DISCARD" -> new ThreadPoolExecutor.DiscardPolicy();
            case "DISCARD_OLDEST" -> new ThreadPoolExecutor.DiscardOldestPolicy();
            case "CALLER_RUNS" -> new ThreadPoolExecutor.CallerRunsPolicy();
            default -> throw new IllegalStateException(
                    "Unsupported rejection policy: " + REJECTION_POLICY
            );
        };
    }

    /**
     * Submits a task and reports whether it was accepted for execution.
     * CALLER_RUNS is accepted when the task starts synchronously in the caller.
     */
    public static SubmitResult submit(Runnable task) {
        Objects.requireNonNull(task, "task");

        synchronized (POOL) {
            if (SHUTDOWN_STARTED.get() || POOL.isShutdown()) {
                REJECTED_TASK_COUNTER.increment();
                return SubmitResult.SHUTDOWN;
            }

            try {
                POOL.execute(task);
                return SubmitResult.ACCEPTED;
            } catch (RejectedExecutionException e) {
                REJECTED_TASK_COUNTER.increment();
                return POOL.isShutdown()
                        ? SubmitResult.SHUTDOWN
                        : SubmitResult.REJECTED;
            }
        }
    }

    public static ExecutorService get() {
        return POOL;
    }

    public static void shutdown() {
        synchronized (POOL) {
            if (!SHUTDOWN_STARTED.compareAndSet(false, true)) {
                return;
            }

            logger.info(
                    LocaleUtil.getString(
                            "worker_pool_shutdown_initiated"
                    )
            );

            POOL.shutdown();
        }

        try {
            if (!POOL.awaitTermination(10, TimeUnit.SECONDS)) {
                logger.warn(
                        "WorkerPool did not terminate in time, "
                                + "forcing shutdown"
                );
                POOL.shutdownNow();
            }

            TASK_QUEUE.clear();
            logRejectedTasks();

            logger.info(
                    LocaleUtil.getString(
                            "worker_pool_shutdown_completed"
                    )
            );
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            POOL.shutdownNow();
            TASK_QUEUE.clear();
            logRejectedTasks();

            logger.info(
                    LocaleUtil.getString(
                            "worker_pool_shutdown_completed"
                    )
            );
        }
    }

    private static void logRejectedTasks() {
        long rejected =
                REJECTED_TASK_COUNTER.sumThenReset();

        if (rejected > 0) {
            logger.warn(
                    "WorkerPool rejected tasks: total={}, "
                            + "queueSize={}, queueCapacity={}",
                    rejected,
                    TASK_QUEUE.size(),
                    QUEUE_SIZE
            );
        }
    }

    private static int readPositiveInt(
            String key,
            int defaultValue,
            String description
    ) {
        try {
            int value = getConfig().getInt(key);

            if (value > 0) {
                return value;
            }

            logger.warn(
                    "Invalid or missing {} ({}), using default {}",
                    description,
                    key,
                    defaultValue
            );
        } catch (Exception e) {
            logger.warn(
                    "Cannot read {} ({}), using default {}",
                    description,
                    key,
                    defaultValue
            );
        }

        return defaultValue;
    }

    private static String readRejectionPolicy(
            String key,
            String defaultValue
    ) {
        try {
            String value = getConfig().get(key);

            if (value == null || value.isBlank()) {
                return defaultValue;
            }

            String normalized =
                    value.trim().toUpperCase(Locale.ROOT);

            return switch (normalized) {
                case "ABORT", "DISCARD", "DISCARD_OLDEST", "CALLER_RUNS" -> normalized;
                default -> {
                    logger.warn(
                            "Unknown rejection policy {}, using {}",
                            value,
                            defaultValue
                    );
                    yield defaultValue;
                }
            };
        } catch (Exception e) {
            return defaultValue;
        }
    }

    public enum SubmitResult {
        ACCEPTED,
        REJECTED,
        SHUTDOWN
    }
}