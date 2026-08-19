package ru.galkov.servers;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
/**
 * ✅ П.26: Общий worker pool для DNS + Proxy
 */
public final class WorkerPool {
    private static final ExecutorService POOL = Executors.newFixedThreadPool(
            getConfig().getInt("dns.thread.num"),
            r -> {
                Thread t = new Thread(r, "Worker-Pool-Thread");
                t.setDaemon(true);
                return t;
            }
    );

    private WorkerPool() {}

    public static ExecutorService get() {
        return POOL;
    }

    public static void shutdown() {
        POOL.shutdown();
    }
}