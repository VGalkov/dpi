package ru.galkov.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

public final class ClientCounterMap {
    private final ConcurrentMap<String, AtomicInteger> counters = new ConcurrentHashMap<>();

    public AtomicInteger getOrCreate(String clientIp) {
        return counters.computeIfAbsent(clientIp, ignored -> new AtomicInteger());
    }

    public void decrementAndRemoveIfZero(String clientIp, AtomicInteger counter) {
        int remaining = counter.decrementAndGet();
        if (remaining <= 0) counters.remove(clientIp, counter);
    }

    public void removeZeroCounters() {
        counters.entrySet().removeIf(entry -> entry.getValue().get() <= 0);
    }

    public int size() {
        return counters.size();
    }
}