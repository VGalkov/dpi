package ru.galkov.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 *
 * DomainTrie с режимами правил:
 * - EXACT: блокирует только сам домен;
 * - WILDCARD: блокирует только поддомены;
 * - SUBTREE: блокирует домен и все поддомены.
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
        private boolean exactBlocked;
        private boolean wildcardBlocked;
        private boolean subtreeBlocked;
    }

    private static final int MAX_LABELS_CACHE_SIZE = 10_000;

    private static final Map<String, String[]> labelsCache =
            Collections.synchronizedMap(
                    new LinkedHashMap<String, String[]>(
                            MAX_LABELS_CACHE_SIZE, 0.75f, true
                    ) {
                        @Override
                        protected boolean removeEldestEntry(
                                Map.Entry<String, String[]> eldest
                        ) {
                            return size() > MAX_LABELS_CACHE_SIZE;
                        }
                    }
            );

    public synchronized void addDomain(String domain, MatchType matchType) {
        if (matchType == null) {
            return;
        }

        String normalized = normalizeDomain(domain);
        if (normalized == null) {
            return;
        }

        String[] labels = getLabelsCached(normalized);
        if (labels.length == 0) {
            return;
        }

        TrieNode node = root;

        for (int i = labels.length - 1; i >= 0; i--) {
            TrieNode child = node.children.get(labels[i]);

            if (child == null) {
                child = new TrieNode();
                node.children.put(labels[i], child);
            }

            node = child;
        }

        switch (matchType) {
            case EXACT -> node.exactBlocked = true;
            case WILDCARD -> node.wildcardBlocked = true;
            case SUBTREE -> node.subtreeBlocked = true;
        }
    }

    public synchronized boolean matches(String domain) {
        String normalized = normalizeDomain(domain);
        if (normalized == null) {
            return false;
        }

        String[] labels = getLabelsCached(normalized);
        if (labels.length == 0) {
            return false;
        }

        TrieNode node = root;

        for (int i = labels.length - 1; i >= 0; i--) {
            node = node.children.get(labels[i]);

            if (node == null) {
                return false;
            }

            if (node.subtreeBlocked) {
                return true;
            }

            if (i == 0 && node.exactBlocked) {
                return true;
            }

            if (i > 0 && node.wildcardBlocked) {
                return true;
            }
        }

        return false;
    }

    private static String normalizeDomain(String domain) {
        if (domain == null) {
            return null;
        }

        String normalized = domain.trim().toLowerCase(Locale.ROOT);

        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        return normalized.isEmpty() ? null : normalized;
    }

    private static String[] getLabelsCached(String domain) {
        synchronized (labelsCache) {
            String[] labels = labelsCache.get(domain);

            if (labels != null) {
                return labels;
            }

            labels = splitByDot(domain);
            labelsCache.put(domain, labels);
            return labels;
        }
    }

    private static String[] splitByDot(String domain) {
        int dots = 0;

        for (int i = 0; i < domain.length(); i++) {
            if (domain.charAt(i) == '.') {
                dots++;
            }
        }

        if (dots == 0) {
            return new String[]{domain};
        }

        String[] labels = new String[dots + 1];
        int start = 0;
        int index = 0;

        for (int i = 0; i <= domain.length(); i++) {
            if (i == domain.length() || domain.charAt(i) == '.') {
                labels[index++] = domain.substring(start, i);
                start = i + 1;
            }
        }

        return labels;
    }

    public static void clearCache() {
        synchronized (labelsCache) {
            labelsCache.clear();
        }
    }
}