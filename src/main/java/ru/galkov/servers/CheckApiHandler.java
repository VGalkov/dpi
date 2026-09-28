package ru.galkov.servers;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.BlacklistSnapshot;
import ru.galkov.util.BlockDecision;
import ru.galkov.util.HostNormalizer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public final class CheckApiHandler implements HttpHandler {
    private static final Logger logger = LoggerFactory.getLogger(CheckApiHandler.class);
    private static final int MAX_INPUT_LENGTH = 253;
    private static final int MAX_RESPONSE_LENGTH = 4096;
    private static final int MAX_REQUESTS_PER_SECOND = 100;

    private final BlacklistLoader blacklistLoader;
    private final Map<String, AtomicLong> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> lastRequestTime = new ConcurrentHashMap<>();

    public CheckApiHandler(BlacklistLoader blacklistLoader, int port) {
        this.blacklistLoader = blacklistLoader;
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

        logger.debug("[CHECK-API] Request from {}: value={}", clientIp, valueToCheck);

        BlockDecision decision;
        String checkType;
        List<String> checkedIps = new ArrayList<>();

        // ✅ Проверяем, является ли значение IP-адресом
        boolean isIp = HostNormalizer.isIpLiteralFast(valueToCheck);

        if (isIp) {
            // ✅ Проверка IP (exact + CIDR)
            checkType = "ip";
            decision = blacklistLoader.snapshot().checkIp(valueToCheck);
            logger.debug("[CHECK-API] IP check: {} -> blocked={}, source={}, reason={}",
                    valueToCheck, decision.isBlocked(), decision.getSource(), decision.getReason());
        } else {
            // ✅ Проверка домена через DNS-резолв + проверка IP (как в DNS-фильтрации)
            checkType = "domain";

            String normalized = HostNormalizer.normalizeHost(valueToCheck);
            if (normalized == null) {
                decision = BlockDecision.allow();
                logger.debug("[CHECK-API] Invalid domain format: {}", valueToCheck);
            } else {
                decision = checkDomainWithDns(normalized, checkedIps);
                logger.debug("[CHECK-API] Domain check: {} -> blocked={}, source={}, reason={}, rule={}, ipsChecked={}",
                        normalized, decision.isBlocked(), decision.getSource(),
                        decision.getReason(), decision.getMatchedRule(), checkedIps.size());
            }
        }

        if (decision == null) decision = BlockDecision.allow();

        String jsonResponse = buildJsonResponse(checkType, valueToCheck, decision, checkedIps);
        if (jsonResponse.length() > MAX_RESPONSE_LENGTH) {
            jsonResponse = jsonResponse.substring(0, MAX_RESPONSE_LENGTH) + "\"}";
        }

        sendResponse(exchange, 200, jsonResponse);
    }

    /**
     * Проверка домена с DNS-резолвом и проверкой IP-адресов (как в DNS-фильтрации).
     */
    private BlockDecision checkDomainWithDns(String domain, List<String> checkedIps) {
        BlacklistSnapshot snapshot = blacklistLoader.snapshot();

        // 1. Проверяем сам домен
        BlockDecision domainDecision = snapshot.checkDomain(domain);
        if (domainDecision.isBlocked()) {
            logger.debug("[CHECK-API-DNS] Domain blocked directly: {}", domain);
            return domainDecision;
        }

        // 2. Делаем DNS-запрос (A и AAAA записи)
        try {
            InetAddress[] addresses = InetAddress.getAllByName(domain);
            if (addresses != null && addresses.length > 0) {
                for (InetAddress addr : addresses) {
                    String ip = addr.getHostAddress();
                    checkedIps.add(ip);

                    // 3. Проверяем каждый IP через blacklist (exact + CIDR)
                    BlockDecision ipDecision = snapshot.checkIp(ip);
                    if (ipDecision.isBlocked()) {
                        logger.debug("[CHECK-API-DNS] Domain {} blocked by IP: {} (source={}, reason={})",
                                domain, ip, ipDecision.getSource(), ipDecision.getReason());
                        return ipDecision;
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("[CHECK-API-DNS] DNS resolution failed for {}: {}", domain, e.getMessage());
        }

        // 4. Если ни домен, ни IP не заблокированы — разрешаем
        logger.debug("[CHECK-API-DNS] Domain {} allowed (no matches in blacklist)", domain);
        return BlockDecision.allow();
    }

    private void sendHtmlForm(HttpExchange exchange) throws IOException {
        String html = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Check API</title>" +
                "<style>body{font-family:Arial,sans-serif;margin:40px}input{padding:8px;width:400px}button{padding:8px 16px}#result{margin-top:20px;padding:10px;border:1px solid #ccc;display:none}.info{color:#666;font-size:12px;margin-top:10px}</style></head>" +
                "<body><h1>Domain/IP Check</h1>" +
                "<form id=\"checkForm\">" +
                "<input type=\"text\" id=\"value\" name=\"check\" placeholder=\"Enter domain or IP\" required>" +
                "<button type=\"submit\">Check</button></form>" +
                "<div id=\"result\"></div>" +
                "<div class=\"info\">Checks domain + resolves IPs and checks them (same algorithm as DNS filtering)</div>" +
                "<script>document.getElementById('checkForm').addEventListener('submit',async e=>{e.preventDefault();const v=document.getElementById('value').value;if(!v)return;try{const r=await fetch('/check?check='+encodeURIComponent(v));const j=await r.json();document.getElementById('result').style.display='block';if(j.blocked){document.getElementById('result').innerHTML='<strong style=\"color:red\">BLOCKED</strong><br><strong>Type:</strong> '+j.type+'<br><strong>Value:</strong> '+j.value+(j.checkedIps?'<br><strong>Checked IPs:</strong> '+j.checkedIps.join(', '):'')+'<br><strong>Source:</strong> '+j.source+'<br><strong>Reason:</strong> '+j.reason+'<br><strong>Rule:</strong> '+j.rule;}else{document.getElementById('result').innerHTML='<strong style=\"color:green\">ALLOWED</strong><br><strong>Type:</strong> '+j.type+'<br><strong>Value:</strong> '+j.value+(j.checkedIps?'<br><strong>Checked IPs:</strong> '+j.checkedIps.join(', '):'');}}catch(e){document.getElementById('result').style.display='block';document.getElementById('result').innerHTML='<strong>Error:</strong> '+e.message;}});</script></body></html>";
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

    private String buildJsonResponse(String type, String value, BlockDecision decision, List<String> checkedIps) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"blocked\":").append(decision.isBlocked());
        sb.append(",\"type\":\"").append(type).append("\"");
        sb.append(",\"value\":\"").append(escapeJson(value)).append("\"");
        if (!checkedIps.isEmpty()) {
            sb.append(",\"checkedIps\":[");
            for (int i = 0; i < checkedIps.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\"").append(escapeJson(checkedIps.get(i))).append("\"");
            }
            sb.append("]");
        }
        if (decision.isBlocked()) {
            sb.append(",\"source\":\"").append(escapeJson(decision.getSource())).append("\"");
            sb.append(",\"reason\":\"").append(escapeJson(decision.getReason().name())).append("\"");
            sb.append(",\"rule\":\"").append(escapeJson(decision.getMatchedRule())).append("\"");
            sb.append(",\"action\":\"").append(escapeJson(decision.getAction().name())).append("\"");
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