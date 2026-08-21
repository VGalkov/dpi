package ru.galkov.llm;

import java.util.Locale;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public final class HttpQueryRecord implements QueryRecord {
    private static final int MAX_STRING_LENGTH = 16_384;

    private final String clientIp;
    private final String method;
    private final String host;
    private final int port;
    private final String path;
    private final String headers;
    private final String body;
    private final long timestamp;

    private final int pathLength;
    private final int headerLength;
    private final int bodyLength;
    private final boolean https;
    private final boolean hostIsIp;
    private final boolean suspiciousTld;
    private final boolean pathHasTraversal;
    private final boolean pathHasInjectionMarkers;
    private final boolean bodyHasInjectionMarkers;
    private final boolean suspiciousUserAgent;

    public HttpQueryRecord(
            String clientIp,
            String method,
            String host,
            int port,
            String path,
            String headers,
            String body,
            long timestamp
    ) {
        this.clientIp = QueryRecordUtils.normalize(clientIp);
        this.method = normalizeMethod(method);
        this.host = QueryRecordUtils.normalizeHost(host);
        this.port = port;
        this.path = QueryRecordUtils.limit(QueryRecordUtils.normalize(path), MAX_STRING_LENGTH);
        this.headers = QueryRecordUtils.limit(QueryRecordUtils.normalize(headers), MAX_STRING_LENGTH);
        this.body = QueryRecordUtils.limit(QueryRecordUtils.normalize(body), MAX_STRING_LENGTH);
        this.timestamp = timestamp;

        this.pathLength = this.path.length();
        this.headerLength = this.headers.length();
        this.bodyLength = this.body.length();
        this.https = port == 443;
        this.hostIsIp = QueryRecordUtils.isIpLiteral(this.host);
        this.suspiciousTld = QueryRecordUtils.hasSuspiciousTld(this.host);
        this.pathHasTraversal = QueryRecordUtils.hasPathTraversal(this.path);
        this.pathHasInjectionMarkers = QueryRecordUtils.hasInjectionMarkers(this.path);
        this.bodyHasInjectionMarkers = QueryRecordUtils.hasInjectionMarkers(this.body);
        this.suspiciousUserAgent = QueryRecordUtils.hasSuspiciousUserAgent(this.headers);
    }

    private static String normalizeMethod(String value) {
        String method = QueryRecordUtils.normalize(value).toUpperCase(Locale.ROOT);
        return method.isEmpty() ? "UNKNOWN" : method;
    }

    // ✅ Реализация интерфейса QueryRecord
    @Override
    public String getClientIp() { return clientIp; }

    @Override
    public long getTimestamp() { return timestamp; }

    @Override
    public String getTarget() { return host; }

    @Override
    public int getTargetLength() { return host.length(); }

    @Override
    public boolean isTargetIp() { return hostIsIp; }

    @Override
    public boolean hasSuspiciousTld() { return suspiciousTld; }

    @Override
    public boolean hasInjectionMarkers() { return pathHasInjectionMarkers || bodyHasInjectionMarkers; }

    @Override
    public boolean hasSuspiciousIndicator() { return suspiciousUserAgent; }

    // ✅ Специфичные для HTTP методы
    public String getMethod() { return method; }
    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getPath() { return path; }
    public String getHeaders() { return headers; }
    public String getBody() { return body; }
    public int getPathLength() { return pathLength; }
    public int getHeaderLength() { return headerLength; }
    public int getBodyLength() { return bodyLength; }
    public boolean isHttps() { return https; }
    public boolean isHostIp() { return hostIsIp; }
    public boolean hasPathTraversal() { return pathHasTraversal; }
    public boolean hasPathInjectionMarkers() { return pathHasInjectionMarkers; }
    public boolean hasBodyInjectionMarkers() { return bodyHasInjectionMarkers; }
    public boolean hasSuspiciousUserAgent() { return suspiciousUserAgent; }

    @Override
    public String toString() {
        return "HttpQueryRecord{clientIp='" + clientIp + "', method='" + method +
                "', host='" + host + "', port=" + port + ", path='" + path +
                "', timestamp=" + timestamp + '}';
    }
}