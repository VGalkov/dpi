package ru.galkov.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public final class DomainTrie {

    private final TrieNode root = new TrieNode();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public enum MatchType {EXACT, WILDCARD, SUBTREE}

    private static final class TrieNode {
        private final Map<String, TrieNode> children = new java.util.HashMap<>();
        private boolean exactBlocked;
        private boolean wildcardBlocked;
        private boolean subtreeBlocked;
    }

    private static final int MAX_LABELS_CACHE_SIZE = 10_000;

    private static final Map<String, String[]> labelsCache =
            Collections.synchronizedMap(
                    new LinkedHashMap<String, String[]>(MAX_LABELS_CACHE_SIZE, 0.75f, true) {
                        @Override
                        protected boolean removeEldestEntry(Map.Entry<String, String[]> eldest) {
                            return size() > MAX_LABELS_CACHE_SIZE;
                        }
                    }
            );

    public void addDomain(String domain, MatchType matchType) {
        if (matchType == null) return;
        String normalized = HostNormalizer.normalizeDomain(domain);
        if (normalized == null) return;
        String[] labels = getLabelsCached(normalized);
        if (labels.length == 0) return;

        lock.writeLock().lock();
        try {
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
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean contains(String domain) {
        String normalized = HostNormalizer.normalizeDomain(domain);
        if (normalized == null) return false;
        String[] labels = getLabelsCached(normalized);
        if (labels.length == 0) return false;

        lock.readLock().lock();
        try {
            TrieNode node = root;
            for (int i = labels.length - 1; i >= 0; i--) {
                node = node.children.get(labels[i]);
                if (node == null) return false;
            }
            return node.exactBlocked || node.wildcardBlocked || node.subtreeBlocked;
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean matches(String domain) {
        String normalized = HostNormalizer.normalizeDomain(domain);
        if (normalized == null) return false;
        String[] labels = getLabelsCached(normalized);
        if (labels.length == 0) return false;

        lock.readLock().lock();
        try {
            TrieNode node = root;
            for (int i = labels.length - 1; i >= 0; i--) {
                node = node.children.get(labels[i]);
                if (node == null) return false;
                if (node.subtreeBlocked) return true;
                if (i == 0 && node.exactBlocked) return true;
                if (i > 0 && node.wildcardBlocked) return true;
            }
            return false;
        } finally {
            lock.readLock().unlock();
        }
    }

    public int size() {
        lock.readLock().lock();
        try {
            return countNodes(root);
        } finally {
            lock.readLock().unlock();
        }
    }

    private int countNodes(TrieNode node) {
        if (node == null) return 0;
        int count = (node.exactBlocked || node.wildcardBlocked || node.subtreeBlocked) ? 1 : 0;
        for (TrieNode child : node.children.values()) {
            count += countNodes(child);
        }
        return count;
    }

    private static String[] getLabelsCached(String domain) {
        synchronized (labelsCache) {
            String[] labels = labelsCache.get(domain);
            if (labels != null) return labels;
            labels = HostNormalizer.splitHostToLabels(domain);
            labelsCache.put(domain, labels);
            return labels;
        }
    }
}