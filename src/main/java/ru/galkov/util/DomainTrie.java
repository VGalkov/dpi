package ru.galkov.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * DomainTrie с явными режимами правил:
 * - EXACT: блокирует только сам домен
 * - WILDCARD: блокирует только поддомены (*.example.org)
 * - SUBTREE: блокирует домен и все поддомены
 *
 * ✅ П.4 + П.16: Исправление race condition и неэффективного кэширования
 */
public final class DomainTrie {

    private final TrieNode root = new TrieNode();

    public enum MatchType {
        EXACT,
        WILDCARD,
        SUBTREE
    }

    private static final class TrieNode {
        private final Map<String, TrieNode> children = new java.util.HashMap<>();
        private boolean exactBlocked = false;
        private boolean wildcardBlocked = false;
        private boolean subtreeBlocked = false;
    }

    // ✅ П.4 + П.16: LRU cache с LinkedHashMap вместо ConcurrentHashMap
    private static final int MAX_LABELS_CACHE_SIZE = 10000;
    private static final Map<String, String[]> labelsCache =
            Collections.synchronizedMap(new LinkedHashMap<String, String[]>(MAX_LABELS_CACHE_SIZE, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, String[]> eldest) {
                    return size() > MAX_LABELS_CACHE_SIZE;
                }
            });

    public void addDomain(String domain, MatchType matchType) {
        if (domain == null || domain.isEmpty())
            return;

        // Нормализация домена
        domain = domain.toLowerCase().trim();
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }

        String[] labels = getLabelsCached(domain);

        if (labels.length == 0)
            return;

        TrieNode node = root;

        for (int i = labels.length - 1; i >= 0; i--) {
            String label = labels[i];

            TrieNode child = node.children.get(label);

            if (child == null) {
                child = new TrieNode();
                node.children.put(label, child);
            }

            node = child;
        }

        switch (matchType) {
            case EXACT:
                node.exactBlocked = true;
                break;
            case WILDCARD:
                node.wildcardBlocked = true;
                break;
            case SUBTREE:
                node.subtreeBlocked = true;
                break;
        }
    }

    public boolean matches(String domain) {
        if (domain == null || domain.isEmpty())
            return false;

        // Нормализация домена
        domain = domain.toLowerCase().trim();
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }

        String[] labels = getLabelsCached(domain);

        if (labels.length == 0)
            return false;

        TrieNode node = root;

        for (int i = labels.length - 1; i >= 0; i--) {
            String label = labels[i];

            node = node.children.get(label);

            if (node == null)
                return false;

            if (node.subtreeBlocked)
                return true;

            if (i == 0 && node.exactBlocked)
                return true;

            if (i > 0 && node.wildcardBlocked)
                return true;
        }

        return false;
    }

    /**
     * ✅ П.4 + П.16: Оптимизированное кэширование с LRU eviction
     */
    private static String[] getLabelsCached(String domain) {
        String[] labels = labelsCache.get(domain);
        if (labels != null) {
            return labels;
        }

        // ✅ П.16: computeIfAbsent без ручной очистки — LRU сделает сам
        return labelsCache.computeIfAbsent(domain, k -> splitByDot(domain));
    }

    /**
     * ✅ П.16: Оптимизация — замена split("\\.") на indexOf
     */
    private static String[] splitByDot(String domain) {
        // Считаем количество точек
        int dots = 0;
        for (int i = 0; i < domain.length(); i++) {
            if (domain.charAt(i) == '.') dots++;
        }

        // Если точек нет, возвращаем массив из одного элемента
        if (dots == 0) {
            return new String[]{domain};
        }

        // Разбиваем по точкам
        String[] labels = new String[dots + 1];
        int start = 0, idx = 0;
        for (int i = 0; i <= domain.length(); i++) {
            if (i == domain.length() || domain.charAt(i) == '.') {
                labels[idx++] = domain.substring(start, i);
                start = i + 1;
            }
        }
        return labels;
    }

    /**
     * ✅ П.16: Очистка кэша (вызывать при reload blacklist)
     */
    public static void clearCache() {
        labelsCache.clear();
    }
}