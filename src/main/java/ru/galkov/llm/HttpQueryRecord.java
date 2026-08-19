package ru.galkov.llm;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 * Запись HTTP/HTTPS-соединения или HTTP-запроса для асинхронного LLM-анализа.
 */
public final class HttpQueryRecord {

    private final String clientIp;
    private final String method;
    private final String host;
    private final int port;
    private final String path;
    private final String headers;
    private final String body;
    private final long timestamp;

    public HttpQueryRecord(String clientIp,
                           String method,
                           String host,
                           int port,
                           String path,
                           String headers,
                           String body,
                           long timestamp) {
        this.clientIp = clientIp;
        this.method = method;
        this.host = host;
        this.port = port;
        this.path = path;
        this.headers = headers;
        this.body = body;
        this.timestamp = timestamp;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getMethod() {
        return method;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getPath() {
        return path;
    }

    public String getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public long getTimestamp() {
        return timestamp;
    }
}