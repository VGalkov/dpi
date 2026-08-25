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

/**
 * Simple HTTP API to check if IP or hostname is blocked.
 *
 * Usage:
 *   http://127.0.0.1:3129/?ip=10.0.0.1
 *   http://127.0.0.1:3129/?host=www.cofe.ru
 *   http://127.0.0.1:3129/?check=10.0.0.1
 *   http://127.0.0.1:3129/?check=www.cofe.ru
 *
 * Response:
 *   {"blocked":false,"type":"ip","value":"10.0.0.1","source":null}
 *   {"blocked":true,"type":"domain","value":"ads.example.com","source":"blacklist","reason":"SUBTREE"}
 */
public final class CheckApiHandler implements HttpHandler {

    private static final Logger logger = LoggerFactory.getLogger(CheckApiHandler.class);

    private final BlacklistSnapshot snapshot;
    private final int port;

    public CheckApiHandler(BlacklistSnapshot snapshot, int port) {
        this.snapshot = snapshot;
        this.port = port;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
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

        valueToCheck = URLDecoder.decode(valueToCheck, StandardCharsets.UTF_8);

        logger.debug("Check API request: {}", valueToCheck);

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

        String jsonResponse = buildJsonResponse(type, valueToCheck, decision);
        sendResponse(exchange, 200, jsonResponse);
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
                .replace("\t", "\\t");
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