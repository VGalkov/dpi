package ru.galkov.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Юнит-тесты для DomainTrie.
 * Проверяет: add(), contains(), matches() (exact, wildcard, subtree).
 */
public class DomainTrieTest {

    @Test
    public void testAddAndContainsExact() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example.com", DomainTrie.MatchType.EXACT);
        trie.addDomain("mail.example.com", DomainTrie.MatchType.EXACT);
        trie.addDomain("test.org", DomainTrie.MatchType.EXACT);

        assertTrue(trie.contains("example.com"));
        assertTrue(trie.contains("mail.example.com"));
        assertTrue(trie.contains("test.org"));

        assertFalse(trie.contains("notexample.com"));
        assertFalse(trie.contains("example.net"));
        assertFalse(trie.contains("sub.test.org"));
    }

    @Test
    public void testAddAndMatchesWildcard() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example.com", DomainTrie.MatchType.WILDCARD);
        trie.addDomain("test.org", DomainTrie.MatchType.WILDCARD);

        // Wildcard работает только для поддоменов (не для корневого домена)
        assertFalse(trie.matches("example.com"));
        assertTrue(trie.matches("mail.example.com"));
        assertTrue(trie.matches("sub.mail.example.com"));
        assertFalse(trie.matches("test.org"));
        assertTrue(trie.matches("www.test.org"));

        assertFalse(trie.matches("notexample.com"));
        assertFalse(trie.matches("example.net"));
    }

    @Test
    public void testAddAndMatchesSubtree() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example.com", DomainTrie.MatchType.SUBTREE);
        trie.addDomain("test.org", DomainTrie.MatchType.SUBTREE);

        assertTrue(trie.matches("example.com"));
        assertTrue(trie.matches("mail.example.com"));
        assertTrue(trie.matches("sub.mail.example.com"));
        assertTrue(trie.matches("test.org"));
        assertTrue(trie.matches("www.test.org"));

        assertFalse(trie.matches("notexample.com"));
        assertFalse(trie.matches("example.net"));
    }

    @Test
    public void testEmptyDomain() {
        DomainTrie trie = new DomainTrie();

        assertFalse(trie.contains(""));
        assertFalse(trie.matches(""));
    }

    @Test
    public void testNullDomain() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain(null, DomainTrie.MatchType.EXACT);
        assertFalse(trie.contains(null));
        assertFalse(trie.matches(null));
    }

    @Test
    public void testLongDomain() {
        DomainTrie trie = new DomainTrie();

        String longDomain = "a".repeat(253) + ".com";

        trie.addDomain(longDomain, DomainTrie.MatchType.EXACT);
        assertTrue(trie.contains(longDomain));
    }

    @Test
    public void testSpecialCharacters() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example-test.com", DomainTrie.MatchType.EXACT);
        trie.addDomain("example_test.com", DomainTrie.MatchType.EXACT);

        assertTrue(trie.contains("example-test.com"));
        assertTrue(trie.contains("example_test.com"));
        assertFalse(trie.contains("example--test.com"));
    }

    @Test
    public void testCaseInsensitive() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("Example.COM", DomainTrie.MatchType.EXACT);

        assertTrue(trie.contains("example.com"));
        assertTrue(trie.contains("EXAMPLE.COM"));
        assertTrue(trie.contains("ExAmPlE.CoM"));
    }

    @Test
    public void testTrailingDot() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example.com.", DomainTrie.MatchType.EXACT);

        assertTrue(trie.contains("example.com"));
        assertTrue(trie.contains("example.com."));
    }

    @Test
    public void testWwwPrefix() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("www.example.com", DomainTrie.MatchType.EXACT);

        assertTrue(trie.contains("www.example.com"));
        assertFalse(trie.contains("example.com"));
    }

    @Test
    public void testMultipleLevels() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("a.b.c.d.e.f.g.com", DomainTrie.MatchType.EXACT);

        assertTrue(trie.contains("a.b.c.d.e.f.g.com"));
        assertFalse(trie.contains("b.c.d.e.f.g.com"));
    }

    @Test
    public void testDuplicateAdd() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example.com", DomainTrie.MatchType.EXACT);
        trie.addDomain("example.com", DomainTrie.MatchType.EXACT);

        assertTrue(trie.contains("example.com"));
    }

    @Test
    public void testMixedMatchTypes() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example.com", DomainTrie.MatchType.EXACT);
        trie.addDomain("mail.example.com", DomainTrie.MatchType.WILDCARD);
        trie.addDomain("test.org", DomainTrie.MatchType.SUBTREE);

        assertTrue(trie.contains("example.com"));
        // Wildcard работает только для поддоменов mail.example.com
        assertFalse(trie.matches("mail.example.com"));
        assertTrue(trie.matches("sub.mail.example.com"));
        assertTrue(trie.matches("test.org"));
        assertTrue(trie.matches("www.test.org"));
    }

    @Test
    public void testContainsWithNull() {
        DomainTrie trie = new DomainTrie();

        assertFalse(trie.contains(null));
    }

    @Test
    public void testAddWithInvalidMatchType() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example.com", null);
        assertFalse(trie.contains("example.com"));
    }

    @Test
    public void testMatchesExact() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example.com", DomainTrie.MatchType.EXACT);

        assertTrue(trie.matches("example.com"));
        assertFalse(trie.matches("mail.example.com"));
    }

    @Test
    public void testMatchesWildcardVsSubtree() {
        DomainTrie trie = new DomainTrie();

        trie.addDomain("example.com", DomainTrie.MatchType.WILDCARD);
        trie.addDomain("test.org", DomainTrie.MatchType.SUBTREE);

        // Wildcard работает только для поддоменов
        assertFalse(trie.matches("example.com"));
        assertTrue(trie.matches("mail.example.com"));
        assertTrue(trie.matches("test.org"));
        assertTrue(trie.matches("www.test.org"));
    }

    @Test
    public void testSize() {
        DomainTrie trie = new DomainTrie();

        assertEquals(0, trie.size());

        trie.addDomain("example.com", DomainTrie.MatchType.EXACT);
        assertEquals(1, trie.size());

        trie.addDomain("mail.example.com", DomainTrie.MatchType.EXACT);
        assertEquals(2, trie.size());
    }

    @Test
    public void testConcurrentAccess() throws InterruptedException {
        DomainTrie trie = new DomainTrie();
        Thread t1 = new Thread(() -> {
            for (int i = 0; i < 1000; i++) {
                trie.addDomain("domain" + i + ".com", DomainTrie.MatchType.EXACT);
            }
        });
        Thread t2 = new Thread(() -> {
            for (int i = 0; i < 1000; i++) {
                trie.contains("domain" + i + ".com");
                trie.matches("domain" + i + ".com");
            }
        });

        t1.start();
        t2.start();
        t1.join();
        t2.join();

        assertEquals(1000, trie.size());
    }

    @Test
    public void testLabelsCache() {
        DomainTrie trie = new DomainTrie();

        // Добавить 10,000 доменов (заполнить кэш)
        for (int i = 0; i < 10_000; i++) {
            trie.addDomain("domain" + i + ".com", DomainTrie.MatchType.EXACT);
        }

        // Проверить, что кэш работает (быстрый поиск)
        long start = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            trie.contains("domain" + i + ".com");
        }
        long duration = System.nanoTime() - start;

        assertTrue(duration < 100_000_000, "Кэш должен ускорять поиск");
    }
}