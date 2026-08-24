package ru.galkov.servers;

import ru.galkov.util.ClientCounterMap;
import ru.galkov.util.IoUtil;

import java.net.Socket;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class ConnectionLease
        implements AutoCloseable {

    private final Socket socket;
    private final String clientIp;
    private final ClientCounterMap counters;
    private final AtomicInteger clientCounter;
    private final Semaphore connectionSlots;

    private final AtomicBoolean started =
            new AtomicBoolean();

    private final AtomicBoolean released =
            new AtomicBoolean();

    private ConnectionLease(
            Socket socket,
            String clientIp,
            ClientCounterMap counters,
            AtomicInteger clientCounter,
            Semaphore connectionSlots
    ) {
        this.socket =
                Objects.requireNonNull(
                        socket,
                        "socket"
                );

        this.clientIp =
                Objects.requireNonNull(
                        clientIp,
                        "clientIp"
                );

        this.counters =
                Objects.requireNonNull(
                        counters,
                        "counters"
                );

        this.clientCounter =
                Objects.requireNonNull(
                        clientCounter,
                        "clientCounter"
                );

        this.connectionSlots =
                Objects.requireNonNull(
                        connectionSlots,
                        "connectionSlots"
                );
    }

    /**
     * Creates a lease and increments the client counter.
     *
     * Use this method when the client counter has not yet
     * been reserved.
     */
    static ConnectionLease acquire(
            Socket socket,
            String clientIp,
            ClientCounterMap counters,
            Semaphore connectionSlots
    ) {
        AtomicInteger counter =
                counters.getOrCreate(clientIp);

        counter.incrementAndGet();

        return new ConnectionLease(
                socket,
                clientIp,
                counters,
                counter,
                connectionSlots
        );
    }

    /**
     * Creates a lease for an already reserved counter
     * and semaphore permit.
     *
     * The method does not increment the counter and does
     * not acquire a semaphore permit.
     */
    static ConnectionLease fromReserved(
            Socket socket,
            String clientIp,
            ClientCounterMap counters,
            AtomicInteger clientCounter,
            Semaphore connectionSlots
    ) {
        return new ConnectionLease(
                socket,
                clientIp,
                counters,
                clientCounter,
                connectionSlots
        );
    }

    public Socket socket() {
        return socket;
    }

    public String clientIp() {
        return clientIp;
    }

    /**
     * Atomically grants the handler permission to start.
     *
     * Returns false if the lease was already released.
     */
    public boolean tryStart() {
        if (released.get()) {
            return false;
        }

        return started.compareAndSet(
                false,
                true
        ) && !released.get();
    }

    public boolean isStarted() {
        return started.get();
    }

    public boolean isReleased() {
        return released.get();
    }

    /**
     * Releases all resources exactly once.
     */
    public void release() {
        if (!released.compareAndSet(false, true)) {
            return;
        }

        counters.decrementAndRemoveIfZero(
                clientIp,
                clientCounter
        );

        connectionSlots.release();
        IoUtil.closeQuietly(socket);
    }

    @Override
    public void close() {
        release();
    }
}