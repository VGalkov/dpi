package ru.galkov.llm;

import java.util.Locale;

public final class HttpQueryRecord {
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
        this.clientIp = normalize(clientIp);
        this.method = normalizeMethod(method);
        this.host = normalizeHost(host);
        this.port = port;
        this.path = limit(normalize(path));
        this.headers = limit(normalize(headers));
        this.body = limit(normalize(body));
        this.timestamp = timestamp;

        this.pathLength = this.path.length();
        this.headerLength = this.headers.length();
        this.bodyLength = this.body.length();
        this.https = port == 443;
        this.hostIsIp = isIpLiteral(this.host);
        this.suspiciousTld = hasSuspiciousTld(this.host);
        this.pathHasTraversal = hasPathTraversal(this.path);
        this.pathHasInjectionMarkers =
                hasInjectionMarkers(this.path);
        this.bodyHasInjectionMarkers =
                hasInjectionMarkers(this.body);
        this.suspiciousUserAgent =
                hasSuspiciousUserAgent(this.headers);
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

    public int getPathLength() {
        return pathLength;
    }

    public int getHeaderLength() {
        return headerLength;
    }

    public int getBodyLength() {
        return bodyLength;
    }

    public boolean isHttps() {
        return https;
    }

    public boolean isHostIp() {
        return hostIsIp;
    }

    public boolean hasSuspiciousTld() {
        return suspiciousTld;
    }

    public boolean hasPathTraversal() {
        return pathHasTraversal;
    }

    public boolean hasPathInjectionMarkers() {
        return pathHasInjectionMarkers;
    }

    public boolean hasBodyInjectionMarkers() {
        return bodyHasInjectionMarkers;
    }

    public boolean hasSuspiciousUserAgent() {
        return suspiciousUserAgent;
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }

    private static String normalizeMethod(String value) {
        String method = normalize(value).toUpperCase(Locale.ROOT);
        return method.isEmpty() ? "UNKNOWN" : method;
    }

    private static String normalizeHost(String value) {
        String host = normalize(value).toLowerCase(Locale.ROOT);

        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }

        return host;
    }

    private static String limit(String value) {
        if (value.length() <= MAX_STRING_LENGTH) {
            return value;
        }

        return value.substring(0, MAX_STRING_LENGTH);
    }

    private static boolean isIpLiteral(String value) {
        if (value.isEmpty()) {
            return false;
        }

        if (value.matches(
                "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)"
                        + "(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$"
        )) {
            return true;
        }

        return value.contains(":")
                && value.matches("^[0-9a-f:]+$");
    }

    private static boolean hasSuspiciousTld(String host) {
        return host.endsWith(".xyz")
                || host.endsWith(".top")
                || host.endsWith(".tk")
                || host.endsWith(".club")
                || host.endsWith(".work");
    }

    private static boolean hasPathTraversal(String value) {
        String lower = value.toLowerCase(Locale.ROOT);

        return lower.contains("../")
                || lower.contains("..\\\\")
                || lower.contains("%2e%2e")
                || lower.contains("2e2e2f")
                || lower.contains("2e2e5c");
    }

    private static boolean hasInjectionMarkers(String value) {
        String lower = value.toLowerCase(Locale.ROOT);

        return lower.contains("select ")
                || lower.contains(" union ")
                || lower.contains(" drop ")
                || lower.contains(" insert ")
                || lower.contains(" update ")
                || lower.contains(" delete ")
                || lower.contains(" or 1=1")
                || lower.contains("<script")
                || lower.contains("javascript:")
                || lower.contains("onerror=")
                || lower.contains("onload=")
                || lower.contains("$(")
                || lower.contains(";%00")
                || lower.contains("%0a")
                || lower.contains("%0d")
                || lower.contains("../")
                || lower.contains("..\\\\");
    }

    private static boolean hasSuspiciousUserAgent(String headers) {
        String lower = headers.toLowerCase(Locale.ROOT);

        return lower.contains("user-agent: curl")
                || lower.contains("user-agent: wget")
                || lower.contains("user-agent: python")
                || lower.contains("user-agent: nikto")
                || lower.contains("user-agent: sqlmap")
                || lower.contains("user-agent: nmap");
    }

    @Override
    public String toString() {
        return String.format(
                Locale.ROOT,
                "HttpQueryRecord{clientIp='%s', method='%s', "
                        + "host='%s', port=%d, path='%s', timestamp=%d}",
                clientIp,
                method,
                host,
                port,
                path,
                timestamp
        );
    }
}