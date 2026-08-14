package ru.galkov.util;

/**
 * Результат проверки blacklist с деталями о причине блокировки.
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
        return new BlockDecision(false, BlockReason.NONE, null, null, BlockAction.ALLOW);
    }

    public static BlockDecision blockIpExact(String matchedRule, String source) {
        return new BlockDecision(true, BlockReason.IP_EXACT, matchedRule, source, BlockAction.BLOCK_HTTP_403);
    }

    public static BlockDecision blockIpCidr(String matchedRule, String source) {
        return new BlockDecision(true, BlockReason.IP_CIDR, matchedRule, source, BlockAction.BLOCK_HTTP_403);
    }

    public static BlockDecision blockDomain(DomainTrie.MatchType matchType, String matchedRule, String source) {
        BlockReason reason = switch (matchType) {
            case WILDCARD -> BlockReason.DOMAIN_WILDCARD;
            case SUBTREE -> BlockReason.DOMAIN_SUBTREE;
            default -> BlockReason.DOMAIN_EXACT;
        };
        return new BlockDecision(true, reason, matchedRule, source, BlockAction.BLOCK_HTTP_403);
    }

    public boolean isBlocked() {
        return blocked;
    }

    public String getMatchedRule() {
        return matchedRule;
    }

}