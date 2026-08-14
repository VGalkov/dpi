package ru.galkov.util;

import java.util.HashMap;
import java.util.Map;

/**
 *s0506777@yandex.ru Galkov V.A.
 * DomainTrie с явными режимами правил:
 * - EXACT: блокирует только сам домен
 * - WILDCARD: блокирует только поддомены (*.example.org)
 * - SUBTREE: блокирует домен и все поддомены
 */
public final class DomainTrie {

    private final TrieNode root = new TrieNode();

    public enum MatchType {
        EXACT,
        WILDCARD,
        SUBTREE
    }

    private static final class TrieNode {
        private final Map<String, TrieNode> children = new HashMap<String, TrieNode>();
        private boolean exactBlocked = false;
        private boolean wildcardBlocked = false;
        private boolean subtreeBlocked = false;
    }

    public void addDomain(String domain, MatchType matchType) {
        if (domain == null || domain.isEmpty())
            return;

        String[] labels = splitDomain(domain);

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

        String[] labels = splitDomain(domain);

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

    private static String[] splitDomain(String domain) {
        if (domain == null || domain.isEmpty())
            return new String[0];

        return domain.split("\\.");
    }
}