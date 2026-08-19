package ru.galkov.util;

public final class BlockDecision {
    public enum BlockReason { NONE, IP_EXACT, IP_CIDR, DOMAIN_EXACT, DOMAIN_WILDCARD, DOMAIN_SUBTREE }
    public enum BlockAction { ALLOW, BLOCK_HTTP_403, BLOCK_DROP, BLOCK_SINKHOLE, LOG_ONLY }

    // Кэш для ALLOW
    private static final BlockDecision ALLOW_DECISION = new BlockDecision(false, BlockReason.NONE, null, null, BlockAction.ALLOW);

    // Кэш для заблокированных (без matchedRule)
    private static final BlockDecision BLOCK_IP_EXACT = new BlockDecision(true, BlockReason.IP_EXACT, null, "blacklist", BlockAction.BLOCK_HTTP_403);
    private static final BlockDecision BLOCK_IP_CIDR = new BlockDecision(true, BlockReason.IP_CIDR, null, "blacklist", BlockAction.BLOCK_HTTP_403);
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

    public static BlockDecision blockIpCidr(String rule, String source) {
        return rule != null ? new BlockDecision(true, BlockReason.IP_CIDR, rule, source, BlockAction.BLOCK_HTTP_403) : BLOCK_IP_CIDR;
    }

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
    public String getSource() { return source; }
    public BlockAction getAction() { return action; }
}