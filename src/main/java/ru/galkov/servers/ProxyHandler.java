package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.llm.HttpAnomalyDetector;
import ru.galkov.util.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.StringTokenizer;

import static ru.galkov.Main.getConfig;

public class ProxyHandler implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(ProxyHandler.class);

    private final Socket clientSocket;
    private final String clientIp;
    private final BlacklistLoader blacklist;
    private final int connectTimeout, clientReadTimeout, remoteReadTimeout, maxHeaderBytes;
    private final long maxBodyBytes;
    private static HttpAnomalyDetector httpAnomalyDetector;
    private static final String ERROR_TEMPLATE_STR =
            "HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n<html><body><h1>%d %s</h1></body></html>";

    public ProxyHandler(Socket clientSocket, String clientIp, BlacklistLoader blacklist, HttpAnomalyDetector detector) {
        this.clientSocket = clientSocket;
        this.clientIp = clientIp != null ? clientIp : "unknown";
        this.blacklist = blacklist;
        ProxyHandler.httpAnomalyDetector = detector;
        this.connectTimeout = getConfig().getInt("proxy.connect-timeout-millis");
        this.clientReadTimeout = getConfig().getInt("proxy.client-read-timeout-millis");
        this.remoteReadTimeout = getConfig().getInt("proxy.remote-read-timeout-millis");
        this.maxHeaderBytes = getConfig().getInt("proxy.max-header-bytes");
        this.maxBodyBytes = getConfig().getLong("proxy.max-body-bytes");
        validateLimits();
    }

    @Override
    public void run() {
        try {
            clientSocket.setSoTimeout(clientReadTimeout);
            InputStream in = clientSocket.getInputStream();
            OutputStream out = clientSocket.getOutputStream();
            String firstLine = ProxyHandlerHelper.readLine(in, maxHeaderBytes);
            if (firstLine == null || firstLine.isEmpty()) return;
            logger.trace("{} -> {}", clientIp, firstLine);

            StringTokenizer t = new StringTokenizer(firstLine);
            if (!t.hasMoreTokens()) { sendError(out, 400, "Bad Request"); return; }
            String method = t.nextToken().toUpperCase(Locale.ROOT);
            if (!t.hasMoreTokens()) { sendError(out, 400, "Bad Request (no target)"); return; }
            String target = t.nextToken();

            if ("CONNECT".equals(method)) { handleConnect(in, out, target); return; }
            if ("GET".equals(method) || "POST".equals(method) || "HEAD".equals(method)
                    || "PUT".equals(method) || "DELETE".equals(method)) {
                handleHttp(in, out, firstLine, target, method); return;
            }
            sendError(out, 501, "Not Implemented");
        } catch (ProxyHandlerHelper.RequestTooLargeException e) {
            logger.info("{} <- Headers too large", clientIp);
            sendErrorQuietly(431, "Request Header Fields Too Large");
        } catch (SocketTimeoutException e) {
            logger.info("{} <- Timeout", clientIp);
            sendErrorQuietly(408, "Request Timeout");
        } catch (IOException e) {
            if (!(e instanceof java.net.SocketException)) logger.warn("{} <- {}", clientIp, e.getMessage());
        } catch (Throwable t) {
            logger.error("{} <- Unexpected error", clientIp, t);
        } finally {
            closeQuietly(clientSocket);
        }
    }

    private void validateLimits() {
        if (connectTimeout <= 0 || clientReadTimeout <= 0 || remoteReadTimeout <= 0)
            throw new IllegalArgumentException("Timeouts must be > 0");
        if (maxHeaderBytes < 1024) throw new IllegalArgumentException("max-header-bytes >= 1024");
        if (maxBodyBytes < 0) throw new IllegalArgumentException("max-body-bytes >= 0");
    }

    private void handleConnect(InputStream in, OutputStream out, String target) throws IOException {
        readAndDiscardHeaders(in);
        ProxyHandlerHelper.HostAndPort hp = ProxyHandlerHelper.parseConnectTarget(target);
        if (hp == null || hp.host() == null) { sendError(out, 400, "Bad Request (invalid host and port)"); return; }

        // Сначала проверка blacklist
        BlockDecision decision = checkBlockedHostOrIp(hp.host());
        if (decision.isBlocked()) {
            logger.info("{} {} {} {} {} {}", LogFields.kv("event", "PROXY_CONNECT_BLOCKED"),
                    LogFields.kv("client", clientIp), LogFields.kv("host", hp.host()),
                    LogFields.kv("port", hp.port()), LogFields.kv("reason", "HOST_IP"),
                    LogFields.kv("rule", decision.getMatchedRule()));
            sendError(out, 403, "Forbidden"); return;
        }

        logger.info("{} {} {} {}", LogFields.kv("event", "PROXY_CONNECT"),
                LogFields.kv("client", clientIp), LogFields.kv("host", hp.host()), LogFields.kv("port", hp.port()));

        // Отправка в LLM только если НЕ заблокировано
        if (httpAnomalyDetector != null && httpAnomalyDetector.isEnabled())
            httpAnomalyDetector.recordRequest(clientIp, "CONNECT", hp.host(), hp.port(), "/", "", null);

        Socket remote = new Socket();
        try {
            remote.connect(new InetSocketAddress(hp.host(), hp.port()), connectTimeout);
            remote.setSoTimeout(remoteReadTimeout);
            remote.setTcpNoDelay(true);
            clientSocket.setTcpNoDelay(true);

            out.write("HTTP/1.1 200 Connection established\r\nProxy-Agent: MyProxy\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            byte[] hello = ProxyHandlerHelper.readInitialTlsHandshake(in, clientSocket, clientReadTimeout);
            if (hello == null) { logger.warn("{} -> CONNECT {}:{}: TLS ClientHello not received", clientIp, hp.host(), hp.port()); ProxyHandlerHelper.runTunnel(clientSocket, remote); return; }

            String sni = ProxyHandlerHelper.extractSniFromTlsHandshake(hello);
            if (sni != null && !sni.isEmpty()) {
                logger.info("{} -> CONNECT {}:{}: SNI={}", clientIp, hp.host(), hp.port(), sni);
                BlacklistSnapshot snapshot = blacklist.snapshot();
                BlockDecision sniDecision = snapshot.checkDomain(sni);
                if (sniDecision.isBlocked()) {
                    logger.info("{} {} {} {} {}", LogFields.kv("event", "PROXY_CONNECT_BLOCKED"),
                            LogFields.kv("client", clientIp), LogFields.kv("sni", sni),
                            LogFields.kv("reason", "SNI"), LogFields.kv("rule", sniDecision.getMatchedRule()));
                    closeQuietly(remote); return;
                }
            }

            remote.getOutputStream().write(hello);
            remote.getOutputStream().flush();
            logger.info("{} {} {} {}", LogFields.kv("event", "PROXY_CONNECT_ESTABLISHED"),
                    LogFields.kv("client", clientIp), LogFields.kv("host", hp.host()), LogFields.kv("port", hp.port()));
            ProxyHandlerHelper.runTunnel(clientSocket, remote);
        } catch (SocketTimeoutException e) {
            closeQuietly(remote);
            if (!clientSocket.isClosed()) sendError(out, 504, "Gateway Timeout");
            logger.info("{} {} {} {}", LogFields.kv("event", "PROXY_CONNECT_TIMEOUT"),
                    LogFields.kv("client", clientIp), LogFields.kv("host", hp.host()), LogFields.kv("port", hp.port()));
        } catch (IOException e) {
            closeQuietly(remote);
            if (!clientSocket.isClosed()) sendError(out, 502, "Bad Gateway");
            logger.warn("{} -> Failed CONNECT {}:{}: {}", clientIp, hp.host(), hp.port(), e.getMessage());
        }
    }

    private void handleHttp(InputStream in, OutputStream out, String firstLine, String target, String method) throws IOException {
        HttpHeaders hdrs = readHttpHeaders(in, firstLine);
        ProxyHandlerHelper.HostAndPort hp = ProxyHandlerHelper.resolveHttpTarget(hdrs.hostHeader, target);
        if (hp == null || hp.host() == null) { sendError(out, 400, "Cannot determine target host"); return; }

        // Сначала проверка blacklist
        BlockDecision dec = checkBlockedHostOrIp(hp.host());
        if (dec.isBlocked()) {
            logger.info("{} {} {} {} {} {}", LogFields.kv("event", "PROXY_HTTP_BLOCKED"),
                    LogFields.kv("client", clientIp), LogFields.kv("host", hp.host()),
                    LogFields.kv("port", hp.port()), LogFields.kv("reason", "HOST_IP"),
                    LogFields.kv("rule", dec.getMatchedRule()));
            sendError(out, 403, "Forbidden"); return;
        }

        String body = null;
        if (hdrs.contentLength > 0 && hdrs.contentLength <= maxBodyBytes) {
            byte[] b = new byte[(int) hdrs.contentLength];
            int total = 0;
            while (total < b.length) { int r = in.read(b, total, b.length - total); if (r == -1) break; total += r; }
            body = new String(b, StandardCharsets.UTF_8);
        }

        // Отправка в LLM только если НЕ заблокировано
        if (httpAnomalyDetector != null && httpAnomalyDetector.isEnabled())
            httpAnomalyDetector.recordRequest(clientIp, method, hp.host(), hp.port(), ProxyHandlerHelper.extractHttpPath(target), hdrs.rawHeaders, body);

        if (hdrs.expectContinuePresent) {
            if (hdrs.chunked) {
                if (maxBodyBytes <= 0) { sendError(out, 413, "Payload Too Large"); return; }
            } else if (hdrs.contentLength > maxBodyBytes) {
                logger.info("{} {} {} {}", LogFields.kv("event", "PROXY_HTTP_BODY_TOO_LARGE"),
                        LogFields.kv("client", clientIp), LogFields.kv("size", hdrs.contentLength), LogFields.kv("limit", maxBodyBytes));
                sendError(out, 413, "Payload Too Large"); return;
            }
            out.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
        }

        try (Socket remote = new Socket()) {
            remote.connect(new InetSocketAddress(hp.host(), hp.port()), connectTimeout);
            remote.setSoTimeout(remoteReadTimeout);
            OutputStream rOut = remote.getOutputStream();
            InputStream rIn = remote.getInputStream();
            String path = ProxyHandlerHelper.extractHttpPath(target);
            String req = method + " " + path + " HTTP/1.1\r\n" + hdrs.rawHeaders;
            rOut.write(req.getBytes(StandardCharsets.ISO_8859_1));
            if (body != null && !body.isEmpty()) rOut.write(body.getBytes(StandardCharsets.UTF_8));
            else if (hdrs.chunked) ProxyHandlerHelper.relayChunked(in, rOut, maxBodyBytes);
            else if (hdrs.contentLength > 0) {
                if (hdrs.contentLength > maxBodyBytes) {
                    logger.info("{} {} {} {}", LogFields.kv("event", "PROXY_HTTP_BODY_TOO_LARGE"),
                            LogFields.kv("client", clientIp), LogFields.kv("size", hdrs.contentLength), LogFields.kv("limit", maxBodyBytes));
                    sendError(out, 413, "Payload Too Large"); return;
                }
                ProxyHandlerHelper.relayFixed(in, rOut, hdrs.contentLength);
            }
            rOut.flush();
            relayResponse(rIn, out);
        } catch (SocketTimeoutException e) {
            logger.info("{} {} {} {}", LogFields.kv("event", "PROXY_HTTP_UPSTREAM_TIMEOUT"),
                    LogFields.kv("client", clientIp), LogFields.kv("host", hp.host()), LogFields.kv("port", hp.port()));
            sendError(out, 504, "Gateway Timeout");
        }
    }

    private void readAndDiscardHeaders(InputStream in) throws IOException {
        int total = 0;
        String line;
        while ((line = ProxyHandlerHelper.readLine(in, maxHeaderBytes)) != null) {
            total += line.length() + 2;
            if (total > maxHeaderBytes) throw new ProxyHandlerHelper.RequestTooLargeException("CONNECT headers exceed " + maxHeaderBytes + " bytes");
            if (line.isEmpty()) return;
        }
        throw new IOException("Incomplete CONNECT request");
    }

    private BlockDecision checkBlockedHostOrIp(String host) {
        if (blacklist == null || host == null) return BlockDecision.allow();
        BlacklistSnapshot snapshot = blacklist.snapshot();
        BlockDecision ip = snapshot.checkIp(host);
        if (ip.isBlocked()) return ip;
        return snapshot.checkDomain(host);
    }

    private HttpHeaders readHttpHeaders(InputStream in, String firstLine) throws IOException {
        StringBuilder sb = new StringBuilder(firstLine).append("\r\n");

        int total = firstLine.length() + 2;
        String host = null;
        Long contentLen = null;
        boolean chunked = false, expect = false;
        String line;
        while ((line = ProxyHandlerHelper.readLine(in, maxHeaderBytes)) != null && !line.isEmpty()) {
            total += line.length() + 2;
            if (total > maxHeaderBytes) throw new ProxyHandlerHelper.RequestTooLargeException("HTTP headers exceed " + maxHeaderBytes + " bytes");
            sb.append(line).append("\r\n");
            String low = line.toLowerCase(Locale.ROOT);
            if (low.startsWith("host:")) host = line.substring(5).trim();
            else if (low.startsWith("content-length:")) {
                Long v = parseContentLength(line.substring(15).trim());
                if (v == null) throw new IOException("Invalid Content-Length");
                if (contentLen != null && contentLen.longValue() != v.longValue()) throw new IOException("Conflicting Content-Length");
                contentLen = v;
            } else if (low.startsWith("transfer-encoding:") && line.substring(18).trim().toLowerCase(Locale.ROOT).contains("chunked")) chunked = true;
            else if (low.startsWith("expect:") && low.substring(7).trim().equals("100-continue")) expect = true;
        }
        if (line == null) throw new IOException("Incomplete HTTP request headers");
        sb.append("\r\n");
        return new HttpHeaders(sb.toString(), host, contentLen == null ? 0L : contentLen, chunked, expect);
    }

    private Long parseContentLength(String v) {
        if (v == null || v.isEmpty()) return null;
        try { long l = Long.parseLong(v); return l < 0 ? null : l; } catch (NumberFormatException e) { return null; }
    }

    private void relayResponse(InputStream in, OutputStream out) throws IOException {
        String status = ProxyHandlerHelper.readLine(in, maxHeaderBytes);
        if (status == null) { logger.warn("Empty response from upstream"); return; }
        ProxyHandlerHelper.writeLine(out, status);
        long contentLen = -1;
        boolean chunked = false;
        String line;
        while ((line = ProxyHandlerHelper.readLine(in, maxHeaderBytes)) != null && !line.isEmpty()) {
            ProxyHandlerHelper.writeLine(out, line);
            String low = line.toLowerCase(Locale.ROOT);
            if (low.startsWith("content-length:")) { Long v = parseContentLength(line.substring(15).trim()); if (v != null) contentLen = v; }
            else if (low.startsWith("transfer-encoding:") && line.substring(18).trim().toLowerCase(Locale.ROOT).contains("chunked")) chunked = true;
        }
        if (line == null) return;
        ProxyHandlerHelper.writeLine(out, "");
        if (chunked) ProxyHandlerHelper.relayChunked(in, out, Long.MAX_VALUE);
        else if (contentLen >= 0) ProxyHandlerHelper.relayFixed(in, out, contentLen);
        else ProxyHandlerHelper.relayUntilEof(in, out);
        out.flush();
    }

    private void sendErrorQuietly(int code, String msg) {
        try { if (!clientSocket.isClosed()) sendError(clientSocket.getOutputStream(), code, msg); } catch (IOException ignored) {}
    }

    private void sendError(OutputStream out, int code, String msg) throws IOException {
        String body = "<h1>" + code + " " + msg + "</h1>";
        String resp = String.format(ERROR_TEMPLATE_STR, code, msg, body.getBytes(StandardCharsets.UTF_8).length, code, msg);
        out.write(resp.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private void closeQuietly(Socket s) {
        if (s == null) return;
        try { s.close(); } catch (IOException e) { logger.trace("Socket close error: {}", e.getMessage()); }
    }

    private static final class HttpHeaders {
        private final String rawHeaders;
        private final String hostHeader;
        private final long contentLength;
        private final boolean chunked;
        private final boolean expectContinuePresent;
        private HttpHeaders(String rawHeaders, String hostHeader, long contentLength, boolean chunked, boolean expectContinuePresent) {
            this.rawHeaders = rawHeaders; this.hostHeader = hostHeader; this.contentLength = contentLength; this.chunked = chunked; this.expectContinuePresent = expectContinuePresent;
        }
    }
}