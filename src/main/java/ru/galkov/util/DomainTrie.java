package ru.galkov.util;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class DomainTrie {
    private final TrieNode root = new TrieNode();

    public enum MatchType { EXACT, WILDCARD, SUBTREE }

    private static final class TrieNode {
        private final Map<String, TrieNode> children = new HashMap<>();
        private boolean exactBlocked, wildcardBlocked, subtreeBlocked;
    }

    /**
     * ✅ П.5: Оптимизация — кэширование labels для домена
     */
    private static final Map<String, String[]> labelsCache = new ConcurrentHashMap<>(1024);
    private static final int MAX_LABELS_CACHE_SIZE = 10000;

    public void addDomain(String domain, MatchType type) {
        if (domain == null || domain.isEmpty()) return;

        // Нормализация домена
        domain = domain.toLowerCase().trim();
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }

        String[] labels = getLabelsCached(domain);
        TrieNode node = root;
        for (int i = labels.length - 1; i >= 0; i--) {
            node = node.children.computeIfAbsent(labels[i], k -> new TrieNode());
        }
        switch (type) {
            case EXACT: node.exactBlocked = true; break;
            case WILDCARD: node.wildcardBlocked = true; break;
            case SUBTREE: node.subtreeBlocked = true; break;
        }
    }

    public boolean matches(String domain) {
        if (domain == null || domain.isEmpty()) return false;

        // Нормализация домена
        domain = domain.toLowerCase().trim();
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }

        String[] labels = getLabelsCached(domain);
        TrieNode node = root;
        for (int i = labels.length - 1; i >= 0; i--) {
            node = node.children.get(labels[i]);
            if (node == null) return false;
            if (node.subtreeBlocked) return true;
            if (i == 0 && node.exactBlocked) return true;
            if (i > 0 && node.wildcardBlocked) return true;
        }
        return false;
    }

    /**
     * ✅ П.5: Оптимизация — кэширование split результатов с синхронизацией
     */
    private String[] getLabelsCached(String domain) {
        String[] labels = labelsCache.get(domain);
        if (labels != null) {
            return labels;
        }

        // ✅ П.5: Используем computeIfAbsent для атомарной записи
        return labelsCache.computeIfAbsent(domain, k -> {
            String[] result = splitByDot(domain);
            // ✅ П.5: Ограничение размера кэша
            if (labelsCache.size() > MAX_LABELS_CACHE_SIZE) {
                labelsCache.clear();
            }
            return result;
        });
    }

    /**
     *  Оптимизация: замена split("\\.") на indexOf
     */
    private String[] splitByDot(String domain) {
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
     *  Очистка кэша (вызывать при reload blacklist)
     */
    public static void clearCache() {
        labelsCache.clear();
    }
}