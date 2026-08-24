package ru.galkov.util;

/**
 * Result of a blacklist lookup.
 *
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class BlockDecision {
    public enum BlockReason {
        NONE,
        IP_EXACT,
        IP_CIDR,
        DOMAIN_EXACT,
        DOMAIN_WILDCARD,
        DOMAIN_SUBTREE
    }

    public enum BlockAction {
        ALLOW,
        BLOCK_HTTP_403,
        BLOCK_DROP,
        BLOCK_SINKHOLE,
        LOG_ONLY
    }

    private static final BlockDecision ALLOW_DECISION =
            new BlockDecision(
                    false,
                    BlockReason.NONE,
                    null,
                    null,
                    BlockAction.ALLOW
            );

    private final boolean blocked;
    private final BlockReason reason;
    private final String matchedRule;
    private final String source;
    private final BlockAction action;

    private BlockDecision(
            boolean blocked,
            BlockReason reason,
            String matchedRule,
            String source,
            BlockAction action
    ) {
        this.blocked = blocked;
        this.reason = reason;
        this.matchedRule = matchedRule;
        this.source = source;
        this.action = action;
    }

    public static BlockDecision allow() {
        return ALLOW_DECISION;
    }

    public static BlockDecision blockIpExact(
            String rule,
            String source
    ) {
        return blocked(
                BlockReason.IP_EXACT,
                rule,
                source
        );
    }

    public static BlockDecision blockIpCidr(
            String rule,
            String source
    ) {
        return blocked(
                BlockReason.IP_CIDR,
                rule,
                source
        );
    }

    public static BlockDecision blockDomain(
            DomainTrie.MatchType type,
            String rule,
            String source
    ) {
        if (type == null) {
            type = DomainTrie.MatchType.EXACT;
        }

        BlockReason reason =
                switch (type) {
                    case WILDCARD ->
                            BlockReason.DOMAIN_WILDCARD;

                    case SUBTREE ->
                            BlockReason.DOMAIN_SUBTREE;

                    case EXACT ->
                            BlockReason.DOMAIN_EXACT;
                };

        return blocked(
                reason,
                rule,
                source
        );
    }

    private static BlockDecision blocked(
            BlockReason reason,
            String rule,
            String source
    ) {
        return new BlockDecision(
                true,
                reason,
                rule,
                source == null
                        ? "blacklist"
                        : source,
                BlockAction.BLOCK_HTTP_403
        );
    }

    public boolean isBlocked() {
        return blocked;
    }

    public String getMatchedRule() {
        return matchedRule;
    }

    public String getSource() {
        return source;
    }

    public BlockReason getReason() {
        return reason;
    }

    public BlockAction getAction() {
        return action;
    }

    @Override
    public String toString() {
        if (!blocked) {
            return "BlockDecision{ALLOW}";
        }

        return "BlockDecision{" +
                "blocked=true" +
                ", reason=" + reason +
                ", rule='" + matchedRule + '\'' +
                ", source='" + source + '\'' +
                ", action=" + action +
                '}';
    }
}