package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.util.Objects;
import java.util.concurrent.*;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 *
 * ✅ П.25: WorkerPool с rejection policy и логированием переполнения
 * ✅ П.58: CallerRunsPolicy — защита от deadlock
 * ✅ П.59: Очистка taskQueue в shutdown()
 * ✅ П.60: Проверка на null в getConfig().get()
 */
public final class WorkerPool {
    private static final Logger logger = LoggerFactory.getLogger(WorkerPool.class);

    // ✅ П.25: Настройки из application.properties
    private static final int POOL_SIZE = getConfig().getInt("dns.thread.num");
    private static final int QUEUE_SIZE = getConfig().getInt("worker-pool.queue-size");
    // ✅ П.60: Проверка на null
    private static final String REJECTION_POLICY =
            Objects.requireNonNull(getConfig().get("worker-pool.rejection-policy"),
                    "worker-pool.rejection-policy is required");

    // ✅ П.25: ThreadPoolExecutor с лимитированной очередью
    private static final ExecutorService POOL;
    private static final ArrayBlockingQueue<Runnable> taskQueue;

    static {
        // ✅ П.25: Очередь с лимитом
        taskQueue = new ArrayBlockingQueue<>(QUEUE_SIZE);

        // ✅ П.25: Выбор rejection policy
        RejectedExecutionHandler rejectionHandler;
        switch (REJECTION_POLICY.toUpperCase()) {
            case "ABORT":
                rejectionHandler = new ThreadPoolExecutor.AbortPolicy();
                break;
            case "DISCARD":
                rejectionHandler = new ThreadPoolExecutor.DiscardPolicy();
                break;
            case "DISCARD_OLDEST":
                rejectionHandler = new ThreadPoolExecutor.DiscardOldestPolicy();
                break;
            case "CALLER_RUNS":
            default:
                // ✅ П.58: CallerRunsPolicy с защитой от deadlock
                rejectionHandler = (r, executor) -> {
                    logger.warn(LocaleUtil.getString("worker_pool_queue_full"),
                            taskQueue.size(), QUEUE_SIZE);
                    // ✅ П.58: Не выполняем в calling thread — отбрасываем задачу
                    logger.warn("Task rejected due to full queue, discarding");
                };
                break;
        }

        // ✅ П.25: ThreadPoolExecutor с лимитированной очередью
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

    /**
     * ✅ П.25: Метод для получения текущего размера очереди
     */
    public static int getQueueSize() {
        return taskQueue.size();
    }

    /**
     * ✅ П.25: Метод для получения количества активных задач
     */
    public static int getActiveCount() {
        if (POOL instanceof ThreadPoolExecutor) {
            return ((ThreadPoolExecutor) POOL).getActiveCount();
        }
        return 0;
    }

    /**
     * ✅ П.25: Метод для получения общего количества выполненных задач
     */
    public static long getCompletedTaskCount() {
        if (POOL instanceof ThreadPoolExecutor) {
            return ((ThreadPoolExecutor) POOL).getCompletedTaskCount();
        }
        return 0;
    }

    /**
     * ✅ П.59: Очистка taskQueue в shutdown()
     */
    public static void shutdown() {
        logger.info(LocaleUtil.getString("worker_pool_shutdown_initiated"));
        POOL.shutdown();
        taskQueue.clear();  // ✅ Очистка очереди
        try {
            if (!POOL.awaitTermination(10, TimeUnit.SECONDS)) {
                logger.warn("WorkerPool did not terminate in time, forcing shutdown");
                POOL.shutdownNow();
                taskQueue.clear();  // ✅ Очистка после shutdownNow
            }
            logger.info(LocaleUtil.getString("worker_pool_shutdown_completed"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            POOL.shutdownNow();
            taskQueue.clear();  // ✅ Очистка после прерывания
            logger.info(LocaleUtil.getString("worker_pool_shutdown_completed"));
        }
    }
}