package ru.galkov.servers;

import ru.galkov.util.ClientCounterMap;
import ru.galkov.util.IoUtil;

import java.net.Socket;
import java.net.SocketAddress;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public final class ConnectionLease implements AutoCloseable {

    private final Socket socket;
    private final String clientIp;
    private final ClientCounterMap counters;
    private final AtomicInteger clientCounter;
    private final Semaphore connectionSlots;
    private final SocketAddress originalDestination;
    private final int listenedPort;

    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean released = new AtomicBoolean();

    private ConnectionLease(
            Socket socket,
            String clientIp,
            ClientCounterMap counters,
            AtomicInteger clientCounter,
            Semaphore connectionSlots,
            SocketAddress originalDestination,
            int listenedPort
    ) {
        this.socket = Objects.requireNonNull(socket, "socket");
        this.clientIp = Objects.requireNonNull(clientIp, "clientIp");
        this.counters = Objects.requireNonNull(counters, "counters");
        this.clientCounter = Objects.requireNonNull(clientCounter, "clientCounter");
        this.connectionSlots = Objects.requireNonNull(connectionSlots, "connectionSlots");
        this.originalDestination = originalDestination; // может быть null
        this.listenedPort = listenedPort;
    }

    public static ConnectionLease fromReserved(
            Socket socket,
            String clientIp,
            ClientCounterMap counters,
            AtomicInteger clientCounter,
            Semaphore connectionSlots,
            SocketAddress originalDestination,
            int listenedPort
    ) {
        return new ConnectionLease(socket, clientIp, counters, clientCounter, connectionSlots, originalDestination, listenedPort);
    }

    public Socket socket() {
        return socket;
    }

    public String clientIp() {
        return clientIp;
    }

    public SocketAddress originalDestination() {
        return originalDestination;
    }

    public int listenedPort() {
        return listenedPort;
    }

    public boolean tryStart() {
        if (released.get()) return false;
        return started.compareAndSet(false, true) && !released.get();
    }

    public boolean isReleased() {
        return released.get();
    }

    public void release() {
        if (!released.compareAndSet(false, true)) return;
        counters.decrementAndRemoveIfZero(clientIp, clientCounter);
        connectionSlots.release();
        IoUtil.closeQuietly(socket);
    }

    @Override
    public void close() {
        release();
    }
}
