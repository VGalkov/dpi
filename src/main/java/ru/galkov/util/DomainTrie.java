package ru.galkov.util;

import java.util.HashMap;
import java.util.Map;

public final class DomainTrie {
    private final TrieNode root = new TrieNode();

    public enum MatchType { EXACT, WILDCARD, SUBTREE }

    private static final class TrieNode {
        private final Map<String, TrieNode> children = new HashMap<>();
        private boolean exactBlocked, wildcardBlocked, subtreeBlocked;
    }

    public void addDomain(String domain, MatchType type) {
        if (domain == null || domain.isEmpty()) return;
        // Разбиваем один раз при загрузке
        String[] labels = domain.split("\\.");
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
        String[] labels = domain.split("\\.");
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
}