package ru.galkov.stress;

import org.junit.jupiter.api.Test;
import ru.galkov.util.BlacklistSnapshot;
import ru.galkov.util.ClientCounterMap;
import ru.galkov.util.DomainTrie;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Стресс-тест на гонки данных (многопоточность).
 * Проверяет: ClientCounterMap, DomainTrie, BlacklistSnapshot.
 */
public class ConcurrencyStressTest {

    private static final int THREAD_COUNT = 100;
    private static final int OPERATIONS_PER_THREAD = 10_000;

    @Test
    public void testClientCounterMapConcurrency() throws InterruptedException {
        ClientCounterMap counterMap = new ClientCounterMap();
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(THREAD_COUNT);
        AtomicLong errors = new AtomicLong(0);

        for (int i = 0; i < THREAD_COUNT; i++) {
            int threadId = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < OPERATIONS_PER_THREAD; j++) {
                        String clientIp = "192.168.1." + (threadId % 256);
                        try {
                            AtomicInteger counter = counterMap.getOrCreate(clientIp);
                            counter.incrementAndGet();
                            counterMap.decrementAndRemoveIfZero(clientIp, counter);
                        } catch (Exception e) {
                            errors.incrementAndGet();
                            e.printStackTrace();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    errors.incrementAndGet();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        doneLatch.await(60, TimeUnit.SECONDS);
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals(0, errors.get(), "No exceptions should occur during concurrent access");
    }

    @Test
    public void testDomainTrieConcurrency() throws InterruptedException {
        DomainTrie trie = new DomainTrie();
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(THREAD_COUNT);
        AtomicLong errors = new AtomicLong(0);

        for (int i = 0; i < THREAD_COUNT; i++) {
            int threadId = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < OPERATIONS_PER_THREAD; j++) {
                        String domain = "domain" + (threadId + j) + ".com";
                        try {
                            trie.addDomain(domain, DomainTrie.MatchType.EXACT);
                            boolean contains = trie.contains(domain);
                            if (!contains) {
                                errors.incrementAndGet();
                            }
                        } catch (Exception e) {
                            errors.incrementAndGet();
                            e.printStackTrace();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    errors.incrementAndGet();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        doneLatch.await(60, TimeUnit.SECONDS);
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals(0, errors.get(), "No exceptions should occur during concurrent access");
    }

    @Test
    public void testBlacklistSnapshotConcurrency() throws InterruptedException {
        DomainTrie domainTrie = new DomainTrie();
        Set<String> ips = new HashSet<>();
        Set<ru.galkov.util.IpCidr> cidrs = new HashSet<>();

        for (int i = 0; i < 1000; i++) {
            domainTrie.addDomain("domain" + i + ".com", DomainTrie.MatchType.EXACT);
            ips.add("192.168.1." + i);
        }

        BlacklistSnapshot snapshot = new BlacklistSnapshot(domainTrie, ips, cidrs);
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(THREAD_COUNT);
        AtomicLong errors = new AtomicLong(0);
        AtomicLong blockedCount = new AtomicLong(0);

        for (int i = 0; i < THREAD_COUNT; i++) {
            int threadId = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < OPERATIONS_PER_THREAD; j++) {
                        String domain = "domain" + ((threadId + j) % 1000) + ".com";
                        String ip = "192.168.1." + ((threadId + j) % 1000);
                        try {
                            if (snapshot.checkDomain(domain).isBlocked()) {
                                blockedCount.incrementAndGet();
                            }
                            if (snapshot.checkIp(ip).isBlocked()) {
                                blockedCount.incrementAndGet();
                            }
                        } catch (Exception e) {
                            errors.incrementAndGet();
                            e.printStackTrace();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    errors.incrementAndGet();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        doneLatch.await(60, TimeUnit.SECONDS);
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals(0, errors.get(), "No exceptions should occur during concurrent access");
        assertTrue(blockedCount.get() > 0, "Some domains/IPs should be blocked");
    }
}