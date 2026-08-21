package ru.galkov.llm;

/**
 * Общий интерфейс для записей запросов (DNS/HTTP).
 * s0506777@yandex.ru Galkov V.A.
 */
public interface QueryRecord {

    /**
     * IP-адрес клиента.
     */
    String getClientIp();

    /**
     * Временная метка запроса.
     */
    long getTimestamp();

    /**
     * Домен или хост запроса.
     */
    String getTarget();

    /**
     * Длина целевого домена/хоста.
     */
    int getTargetLength();

    /**
     * Является ли хост IP-адресом.
     */
    boolean isTargetIp();

    /**
     * Подозрительный TLD.
     */
    boolean hasSuspiciousTld();

    /**
     * Признаки инъекций в пути/домене.
     */
    boolean hasInjectionMarkers();

    /**
     * Подозрительный User-Agent (для HTTP) или ключевые слова (для DNS).
     */
    boolean hasSuspiciousIndicator();
}