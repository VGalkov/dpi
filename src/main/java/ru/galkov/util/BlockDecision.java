package ru.galkov.util;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class BlockDecision {
    public enum BlockReason { NONE, IP_EXACT, DOMAIN_EXACT, DOMAIN_WILDCARD, DOMAIN_SUBTREE }
    public enum BlockAction { ALLOW, BLOCK_HTTP_403, BLOCK_DROP, BLOCK_SINKHOLE, LOG_ONLY }

    private static final BlockDecision ALLOW_DECISION = new BlockDecision(false, BlockReason.NONE, null, null, BlockAction.ALLOW);
    private static final BlockDecision BLOCK_IP_EXACT = new BlockDecision(true, BlockReason.IP_EXACT, null, "blacklist", BlockAction.BLOCK_HTTP_403);
    private static final BlockDecision BLOCK_DOMAIN_EXACT = new BlockDecision(true, BlockReason.DOMAIN_EXACT, null, "blacklist", BlockAction.BLOCK_HTTP_403);
    private static final BlockDecision BLOCK_DOMAIN_WILDCARD = new BlockDecision(true, BlockReason.DOMAIN_WILDCARD, null, "blacklist", BlockAction.BLOCK_HTTP_403);
    private static final BlockDecision BLOCK_DOMAIN_SUBTREE = new BlockDecision(true, BlockReason.DOMAIN_SUBTREE, null, "blacklist", BlockAction.BLOCK_HTTP_403);

    private final boolean blocked;
    private final BlockReason reason;
    private final String matchedRule;
    private final String source;
    private final BlockAction action;

    private BlockDecision(boolean blocked, BlockReason reason, String matchedRule, String source, BlockAction action) {
        this.blocked = blocked;
        this.reason = reason;
        this.matchedRule = matchedRule;
        this.source = source;
        this.action = action;
    }

    public static BlockDecision allow() {
        return ALLOW_DECISION;
    }

    public static BlockDecision blockIpExact(String rule, String source) {
        return rule != null ? new BlockDecision(true, BlockReason.IP_EXACT, rule, source, BlockAction.BLOCK_HTTP_403) : BLOCK_IP_EXACT;
    }

    // ✅ П.43: blockIpCidr() и кэш BLOCK_IP_CIDR удалены (не используются)

    public static BlockDecision blockDomain(DomainTrie.MatchType type, String rule, String source) {
        BlockReason reason = switch (type) {
            case WILDCARD -> BlockReason.DOMAIN_WILDCARD;
            case SUBTREE -> BlockReason.DOMAIN_SUBTREE;
            default -> BlockReason.DOMAIN_EXACT;
        };
        return rule != null ? new BlockDecision(true, reason, rule, source, BlockAction.BLOCK_HTTP_403)
                : new BlockDecision(true, reason, null, "blacklist", BlockAction.BLOCK_HTTP_403);
    }

    public boolean isBlocked() { return blocked; }
    public String getMatchedRule() { return matchedRule; }
    public BlockReason getReason() { return reason; }

    @Override
    public String toString() {
        if (!blocked) {
            return "BlockDecision{ALLOW}";
        }
        return "BlockDecision{blocked=true, reason=" + reason
                + ", rule='" + matchedRule + '\''
                + ", source='" + source + '\''
                + ", action=" + action + '}';
    }
}