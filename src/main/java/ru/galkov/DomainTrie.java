package ru.galkov;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * s0506777@yandex.ru Galkov V.A.
 * Префиксное дерево для быстрой проверки доменов.
 * Домены хранятся в обратном порядке (com → google → mail).
 * * Пример: "mail.google.com" → com → google → mail (blocked=true)
 */
public final class DomainTrie {

    private final Node root = new Node();

    public void addDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return;
        }

        String[] parts = domain.split("\\.");
        Node current = root;

        // Идём с конца (TLD → поддомены)
        for (int i = parts.length - 1; i >= 0; i--) {
            String part = parts[i].toLowerCase(Locale.ROOT);
            if (part.isEmpty()) {
                continue;
            }
            current = child(current, part);
        }

        current.blocked = true;
    }

    /**
     * Проверяет, заблокирован ли домен или какой-либо его родитель.
     * Пример: "sub.mail.google.com" проверяет com → google → mail → sub
     */
    public boolean isBlocked(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }

        String[] parts = domain.split("\\.");
        Node current = root;

        // Идём с конца, проверяем каждый уровень
        for (int i = parts.length - 1; i >= 0; i--) {
            String part = parts[i].toLowerCase(Locale.ROOT);
            if (part.isEmpty()) {
                continue;
            }
            current = current.children.get(part);
            if (current == null) {
                return false;
            }
            if (current.blocked) {
                return true;
            }
        }

        return false;
    }

    private Node child(Node node, String key) {
        Node child = node.children.get(key);
        if (child == null) {
            child = new Node();
            node.children.put(key, child);
        }
        return child;
    }

    private static class Node {
        private final Map<String, Node> children = new HashMap<>();
        private boolean blocked = false;
    }
}