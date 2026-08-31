package ru.galkov.servers;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.BlacklistSnapshot;
import ru.galkov.util.BlockDecision;
import ru.galkov.util.HostNormalizer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public final class CheckApiHandler implements HttpHandler {
    private static final Logger logger = LoggerFactory.getLogger(CheckApiHandler.class);
    private static final int MAX_INPUT_LENGTH = 253;
    private static final int MAX_RESPONSE_LENGTH = 4096;
    private static final int MAX_REQUESTS_PER_SECOND = 100;
    private final BlacklistSnapshot snapshot;
    private final Map<String, AtomicLong> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> lastRequestTime = new ConcurrentHashMap<>();

    public CheckApiHandler(BlacklistSnapshot snapshot, int port) {
        this.snapshot = snapshot;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
        if (!checkRateLimit(clientIp)) {
            sendResponse(exchange, 429, "{\"error\":\"Rate limit exceeded\"}");
            return;
        }
        try {
            String path = exchange.getRequestURI().getPath();
            if ("/".equals(path) || "/check".equals(path)) {
                String query = exchange.getRequestURI().getQuery();
                if (query == null || query.isBlank()) {
                    sendHtmlForm(exchange);
                    return;
                }
                handleCheck(exchange, query, clientIp);
            } else {
                sendResponse(exchange, 404, "{\"error\":\"Not found\"}");
            }
        } catch (Exception e) {
            logger.error("Check API error from {}: {}", clientIp, e.getMessage(), e);
            sendResponse(exchange, 500, "{\"error\":\"Internal server error\"}");
        }
    }

    private void handleCheck(HttpExchange exchange, String query, String clientIp) throws IOException {
        Map<String, String> params = parseQuery(query);
        String ip = params.get("ip");
        String host = params.get("host");
        String check = params.get("check");
        String valueToCheck = ip != null ? ip : host != null ? host : check;
        if (valueToCheck == null || valueToCheck.isBlank()) {
            sendResponse(exchange, 400, "{\"error\":\"Missing value. Use ?ip=... or ?host=... or ?check=...\"}");
            return;
        }
        if (valueToCheck.length() > MAX_INPUT_LENGTH) {
            sendResponse(exchange, 400, "{\"error\":\"Input too long\"}");
            return;
        }
        valueToCheck = URLDecoder.decode(valueToCheck, StandardCharsets.UTF_8);
        logger.debug("Check API request from {}: {}", clientIp, valueToCheck);
        boolean isIp = HostNormalizer.isIpLiteralFast(valueToCheck);
        BlockDecision decision = isIp ? snapshot.checkIp(valueToCheck) : snapshot.checkDomain(valueToCheck);
        if (decision == null) decision = BlockDecision.allow();
        String jsonResponse = buildJsonResponse(isIp ? "ip" : "domain", valueToCheck, decision);
        if (jsonResponse.length() > MAX_RESPONSE_LENGTH) {
            jsonResponse = jsonResponse.substring(0, MAX_RESPONSE_LENGTH) + "\"}";
        }
        sendResponse(exchange, 200, jsonResponse);
    }

    private void sendHtmlForm(HttpExchange exchange) throws IOException {
        String html = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Check API</title>" +
                "<style>body{font-family:Arial,sans-serif;margin:40px}input{padding:8px;width:300px}button{padding:8px 16px}#result{margin-top:20px;padding:10px;border:1px solid #ccc;display:none}</style></head>" +
                "<body><h1>Domain/IP Check</h1><form id=\"checkForm\"><input type=\"text\" id=\"value\" name=\"check\" placeholder=\"Enter domain or IP\" required><button type=\"submit\">Check</button></form>" +
                "<div id=\"result\"></div><script>document.getElementById('checkForm').addEventListener('submit',async e=>{e.preventDefault();const v=document.getElementById('value').value;if(!v)return;try{const r=await fetch('/check?check='+encodeURIComponent(v));const j=await r.json();document.getElementById('result').style.display='block';document.getElementById('result').innerHTML='<strong>Status:</strong> '+(j.blocked?'BLOCKED':'ALLOWED')+(j.blocked?'<br><strong>Source:</strong> '+j.source+'<br><strong>Reason:</strong> '+j.reason:'');}catch(e){document.getElementById('result').style.display='block';document.getElementById('result').innerHTML='<strong>Error:</strong> '+e.message;}});</script></body></html>";
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(200, html.getBytes(StandardCharsets.UTF_8).length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(html.getBytes(StandardCharsets.UTF_8));
        }
    }

    private boolean checkRateLimit(String clientIp) {
        long now = System.currentTimeMillis();
        AtomicLong count = requestCounts.computeIfAbsent(clientIp, k -> new AtomicLong(0));
        AtomicLong lastTime = lastRequestTime.computeIfAbsent(clientIp, k -> new AtomicLong(now));
        long last = lastTime.get();
        if (now - last > 1000) { count.set(0); lastTime.set(now); }
        return count.incrementAndGet() <= MAX_REQUESTS_PER_SECOND;
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> params = new HashMap<>();
        for (String pair : query.split("&")) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                params.put(key, value);
            }
        }
        return params;
    }

    private String buildJsonResponse(String type, String value, BlockDecision decision) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"blocked\":").append(decision.isBlocked());
        sb.append(",\"type\":\"").append(type).append("\"");
        sb.append(",\"value\":\"").append(escapeJson(value)).append("\"");
        if (decision.isBlocked()) {
            sb.append(",\"source\":\"").append(escapeJson(decision.getSource())).append("\"");
            sb.append(",\"reason\":\"").append(escapeJson(decision.getReason().name())).append("\"");
            sb.append(",\"rule\":\"").append(escapeJson(decision.getMatchedRule())).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                .replace("\r", "\\r").replace("\t", "\\t").replace("<", "\\u003c")
                .replace(">", "\\u003e").replace("&", "\\u0026");
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, response.getBytes(StandardCharsets.UTF_8).length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes(StandardCharsets.UTF_8));
        }
    }
}