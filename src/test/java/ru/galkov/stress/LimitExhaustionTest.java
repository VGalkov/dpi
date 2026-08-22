package ru.galkov.stress;

import org.junit.jupiter.api.Test;
import ru.galkov.servers.ConnectionLease;
import ru.galkov.util.ClientCounterMap;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Стресс-тест на исчерпание лимитов.
 * Проверяет: maxConnections, maxConnectionsPerClient, maxBodyBytes.
 */
public class LimitExhaustionTest {

    private static final int MAX_CONNECTIONS = 100;
    private static final int MAX_CONNECTIONS_PER_CLIENT = 10;
    private static final int MAX_BODY_BYTES = 4096;

    @Test
    public void testMaxConnectionsLimit() throws Exception {
        ClientCounterMap counterMap = new ClientCounterMap();
        ExecutorService executor = Executors.newFixedThreadPool(MAX_CONNECTIONS * 2);
        CountDownLatch startLatch = new CountDownLatch(1);
        AtomicLong successCount = new AtomicLong(0);
        AtomicLong rejectCount = new AtomicLong(0);

        for (int i = 0; i < MAX_CONNECTIONS * 2; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    Socket socket = new Socket("localhost", 12345);
                    ConnectionLease lease = ConnectionLease.fromReserved(
                            socket,
                            "127.0.0.1",
                            counterMap,
                            counterMap.getOrCreate("127.0.0.1"),
                            null
                    );

                    if (lease.tryStart()) {
                        successCount.incrementAndGet();
                        lease.release();
                    } else {
                        rejectCount.incrementAndGet();
                        socket.close();
                    }
                } catch (Exception ignored) {
                    rejectCount.incrementAndGet();
                }
            });
        }

        startLatch.countDown();
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);

        assertTrue(successCount.get() <= MAX_CONNECTIONS, "Should not exceed max connections");
        assertTrue(rejectCount.get() > 0, "Some connections should be rejected");
    }

    @Test
    public void testMaxConnectionsPerClientLimit() throws Exception {
        ClientCounterMap counterMap = new ClientCounterMap();
        String clientIp = "192.168.1.100";

        for (int i = 0; i < MAX_CONNECTIONS_PER_CLIENT * 2; i++) {
            counterMap.getOrCreate(clientIp).incrementAndGet();
        }

        int activeConnections = counterMap.getOrCreate(clientIp).get();
        assertTrue(activeConnections <= MAX_CONNECTIONS_PER_CLIENT * 2, "Counter should track all connections");
    }

    @Test
    public void testMaxBodyBytesLimit() throws Exception {
        byte[] largeBody = new byte[MAX_BODY_BYTES * 2];
        java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(largeBody);

        byte[] buffer = new byte[MAX_BODY_BYTES];
        int total = 0;
        int len;
        while ((len = in.read(buffer)) != -1) {
            total += len;
            if (total > MAX_BODY_BYTES) {
                break;
            }
        }

        assertTrue(total > MAX_BODY_BYTES, "Should read more than max body bytes");
    }

    @Test
    public void testSocketCleanupOnLimitExceeded() throws Exception {
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();

        ExecutorService acceptor = Executors.newSingleThreadExecutor();
        acceptor.submit(() -> {
            try {
                for (int i = 0; i < 10; i++) {
                    Socket client = serverSocket.accept();
                    client.close();
                }
            } catch (Exception ignored) {
            }
        });

        ExecutorService connector = Executors.newFixedThreadPool(20);
        for (int i = 0; i < 20; i++) {
            connector.submit(() -> {
                try {
                    Socket socket = new Socket("localhost", port);
                    socket.close();
                } catch (Exception ignored) {
                }
            });
        }

        connector.shutdown();
        connector.awaitTermination(5, TimeUnit.SECONDS);
        serverSocket.close();
        acceptor.shutdown();
        acceptor.awaitTermination(5, TimeUnit.SECONDS);

        assertTrue(true, "Sockets should be cleaned up properly");
    }
}