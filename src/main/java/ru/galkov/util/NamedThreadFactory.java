package ru.galkov.util;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public final class NamedThreadFactory implements ThreadFactory {
    private final String name;
    private final boolean daemon;
    private final AtomicInteger counter = new AtomicInteger();

    public NamedThreadFactory(String name, boolean daemon) {
        this.name = name;
        this.daemon = daemon;
    }

    @Override
    public Thread newThread(Runnable runnable) {
        Thread thread = new Thread(
                runnable,
                name + "-" + counter.incrementAndGet()
        );
        thread.setDaemon(daemon);
        return thread;
    }
}