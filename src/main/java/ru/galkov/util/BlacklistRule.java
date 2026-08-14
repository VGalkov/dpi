package ru.galkov.util;

/**
 * Galkov V A s0506777@yandex.ru
 * Модель правила blacklist с метаданными.
 */
public final class BlacklistRule {

    public enum RuleType {
        DOMAIN,
        IP,
        URL
    }

    private final RuleType type;
    private final String value;
    private final String source;
    private final String sourceRecordId;
    private final String blockType;

    public BlacklistRule(RuleType type, String value, String source,
                         String sourceRecordId, String blockType) {
        this.type = type;
        this.value = value;
        this.source = source;
        this.sourceRecordId = sourceRecordId;
        this.blockType = blockType;
    }

    public RuleType getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public String getSource() {
        return source;
    }

    public String getSourceRecordId() {
        return sourceRecordId;
    }

    public String getBlockType() {
        return blockType;
    }

    @Override
    public String toString() {
        return "BlacklistRule{type=" + type + ", value=" + value + ", source=" + source + "}";
    }
}