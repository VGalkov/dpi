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
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
  * Simple HTTP API to check if IP or hostname is blocked.
  * Security:
 *   - Rate limiting: 100 requests per second
 *   - Input validation: max 253 chars
 *   - XSS protection: proper JSON escaping
 * Usage:
 *   http://127.0.0.1:3129/?ip=10.0.0.1
 *   http://127.0.0.1:3129/?host=www.cofe.ru
 */
public final class CheckApiHandler implements HttpHandler {

    private static final Logger logger = LoggerFactory.getLogger(CheckApiHandler.class);

    private static final int MAX_INPUT_LENGTH = 253;
    private static final int MAX_RESPONSE_LENGTH = 4096;
    private static final int MAX_REQUESTS_PER_SECOND = 100;
    private final BlacklistSnapshot snapshot;

    // Rate limiting
    private final Map<String, AtomicLong> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> lastRequestTime = new ConcurrentHashMap<>();

    public CheckApiHandler(BlacklistSnapshot snapshot, int port) {
        this.snapshot = snapshot;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();

        // Rate limiting check
        if (!checkRateLimit(clientIp)) {
            sendResponse(exchange, 429, "{\"error\":\"Rate limit exceeded. Max 100 requests per second.\"}");
            return;
        }

        try {
            URI requestUri = exchange.getRequestURI();
            String query = requestUri.getQuery();

            if (query == null || query.isBlank()) {
                sendResponse(exchange, 400, "{\"error\":\"Missing query parameter. Use ?ip=... or ?host=... or ?check=...\"}");
                return;
            }

            Map<String, String> params = parseQuery(query);
            String ip = params.get("ip");
            String host = params.get("host");
            String check = params.get("check");

            String valueToCheck = ip != null ? ip : host != null ? host : check;

            if (valueToCheck == null || valueToCheck.isBlank()) {
                sendResponse(exchange, 400, "{\"error\":\"Missing value. Use ?ip=... or ?host=... or ?check=...\"}");
                return;
            }

            // Input validation
            if (valueToCheck.length() > MAX_INPUT_LENGTH) {
                sendResponse(exchange, 400, "{\"error\":\"Input too long. Max " + MAX_INPUT_LENGTH + " characters.\"}");
                return;
            }

            valueToCheck = URLDecoder.decode(valueToCheck, StandardCharsets.UTF_8);

            logger.debug("Check API request from {}: {}", clientIp, valueToCheck);

            // Determine if it's IP or domain
            boolean isIp = HostNormalizer.isIpLiteralFast(valueToCheck);

            BlockDecision decision;
            String type;

            if (isIp) {
                decision = snapshot.checkIp(valueToCheck);
                type = "ip";
            } else {
                decision = snapshot.checkDomain(valueToCheck);
                type = "domain";
            }

            // Null safety
            if (decision == null) {
                decision = BlockDecision.allow();
            }

            String jsonResponse = buildJsonResponse(type, valueToCheck, decision);

            // Response size limit
            if (jsonResponse.length() > MAX_RESPONSE_LENGTH) {
                jsonResponse = jsonResponse.substring(0, MAX_RESPONSE_LENGTH) + "\"}";
            }

            sendResponse(exchange, 200, jsonResponse);

        } catch (Exception e) {
            logger.error("Check API error from {}: {}", clientIp, e.getMessage(), e);
            sendResponse(exchange, 500, "{\"error\":\"Internal server error\"}");
        }
    }

    private boolean checkRateLimit(String clientIp) {
        long now = System.currentTimeMillis();
        AtomicLong count = requestCounts.computeIfAbsent(clientIp, k -> new AtomicLong(0));
        AtomicLong lastTime = lastRequestTime.computeIfAbsent(clientIp, k -> new AtomicLong(now));

        long last = lastTime.get();
        if (now - last > 1000) {
            // Новая секунда - сброс счётчика
            count.set(0);
            lastTime.set(now);
        }

        long currentCount = count.incrementAndGet();
        return currentCount <= MAX_REQUESTS_PER_SECOND;
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> params = new HashMap<>();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
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
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026");
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