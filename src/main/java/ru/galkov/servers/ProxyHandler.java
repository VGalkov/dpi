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

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 *
 * ✅ П.6: Чтение body потоком для предотвращения OOM
 * ✅ П.10: Проверка SNI Spoofing
 * ✅ П.21: Security Headers для защиты от XSS и clickjacking
 * ✅ П.26: Передача body потоком без конвертации в String
 * ✅ П.29: Убрана дублирующая проверка размера body
 */
public class ProxyHandler implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(ProxyHandler.class);

    private final Socket clientSocket;
    private final String clientIp;
    private final BlacklistLoader blacklist;
    private final int connectTimeout, clientReadTimeout, remoteReadTimeout, maxHeaderBytes;
    private final long maxBodyBytes;
    // ✅ П.6: Порог для потокового чтения body
    private final long streamBodyThreshold;
    private static HttpAnomalyDetector httpAnomalyDetector;

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
        // ✅ П.6: Порог для потокового чтения
        this.streamBodyThreshold = getConfig().getLong("proxy.stream-body-threshold");
        validateLimits();
    }

    @Override
    public void run() {
        logger.debug(LocaleUtil.getString("proxy_handler_started"), clientIp);
        try {
            clientSocket.setSoTimeout(clientReadTimeout);
            InputStream in = clientSocket.getInputStream();
            OutputStream out = clientSocket.getOutputStream();
            String firstLine = ProxyHandlerHelper.readLine(in, maxHeaderBytes);
            if (firstLine == null || firstLine.isEmpty()) return;
            logger.trace("{} -> {}", clientIp, firstLine);

            StringTokenizer t = new StringTokenizer(firstLine);
            if (!t.hasMoreTokens()) {
                logger.warn(LocaleUtil.getString("proxy_handler_invalid_target"), clientIp, firstLine);
                sendError(out, 400, "Bad Request");
                return;
            }
            String method = t.nextToken().toUpperCase(Locale.ROOT);
            if (!t.hasMoreTokens()) {
                logger.warn(LocaleUtil.getString("proxy_handler_invalid_target"), clientIp, firstLine);
                sendError(out, 400, "Bad Request (no target)");
                return;
            }
            String target = t.nextToken();

            if ("CONNECT".equals(method)) { handleConnect(in, out, target); return; }
            if ("GET".equals(method) || "POST".equals(method) || "HEAD".equals(method)
                    || "PUT".equals(method) || "DELETE".equals(method)) {
                handleHttp(in, out, firstLine, target, method); return;
            }
            logger.warn(LocaleUtil.getString("proxy_handler_method_not_implemented"), clientIp, method);
            sendError(out, 501, "Not Implemented");
        } catch (ProxyHandlerHelper.RequestTooLargeException e) {
            logger.info(LocaleUtil.getString("proxy_handler_headers_too_large"), clientIp);
            sendErrorQuietly(431, "Request Header Fields Too Large");
        } catch (SocketTimeoutException e) {
            logger.info(LocaleUtil.getString("proxy_handler_timeout"), clientIp);
            sendErrorQuietly(408, "Request Timeout");
        } catch (IOException e) {
            if (e instanceof java.net.SocketException) {
                logger.debug(LocaleUtil.getString("proxy_handler_socket_error"), clientIp, e.getMessage());
            } else {
                logger.warn("{} <- {}", clientIp, e.getMessage());
            }
        } catch (Throwable t) {
            logger.error(LocaleUtil.getString("proxy_handler_unexpected_error"), clientIp, t);
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
        if (hp == null || hp.host() == null) {
            logger.warn(LocaleUtil.getString("proxy_handler_invalid_target"), clientIp, target);
            sendError(out, 400, "Bad Request (invalid host and port)");
            return;
        }

        BlockDecision decision = checkBlockedHostOrIp(hp.host());
        if (decision.isBlocked()) {
            logger.info(LocaleUtil.getString("proxy_handler_connect_blocked"),
                    clientIp, hp.host(), hp.port(), decision.getReason());
            sendError(out, 403, "Forbidden"); return;
        }

        logger.info("{} {} {} {}", LogFields.kv("event", "PROXY_CONNECT"),
                LogFields.kv("client", clientIp), LogFields.kv("host", hp.host()), LogFields.kv("port", hp.port()));

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
            if (hello == null) {
                logger.warn("{} -> CONNECT {}:{}: TLS ClientHello not received", clientIp, hp.host(), hp.port());
                ProxyHandlerHelper.runTunnel(clientSocket, remote);
                return;
            }

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

                // ✅ П.10: Проверка SNI Spoofing (только логирование)
                String normalizedHost = HostNormalizer.normalizeHost(hp.host());
                String normalizedSni = HostNormalizer.normalizeHost(sni);
                if (normalizedHost != null && normalizedSni != null && !normalizedHost.equals(normalizedSni)) {
                    logger.warn(LocaleUtil.getString("proxy_handler_connect_sni_mismatch"),
                            clientIp, hp.host(), hp.port(), sni);
                }
            }

            remote.getOutputStream().write(hello);
            remote.getOutputStream().flush();
            logger.info(LocaleUtil.getString("proxy_handler_connect_established"),
                    clientIp, hp.host(), hp.port());
            ProxyHandlerHelper.runTunnel(clientSocket, remote);
        } catch (SocketTimeoutException e) {
            closeQuietly(remote);
            if (!clientSocket.isClosed()) sendError(out, 504, "Gateway Timeout");
            logger.info(LocaleUtil.getString("proxy_handler_connect_timeout"),
                    clientIp, hp.host(), hp.port());
        } catch (IOException e) {
            closeQuietly(remote);
            if (!clientSocket.isClosed()) sendError(out, 502, "Bad Gateway");
            logger.warn(LocaleUtil.getString("proxy_handler_connect_failed"), clientIp, hp.host(), hp.port(), e.getMessage());
        }
    }

    /**
     * ✅ П.6: Чтение body потоком для предотвращения OOM
     * ✅ П.26: Передача body потоком без конвертации в String
     * ✅ П.29: Убрана дублирующая проверка размера body
     */
    private void handleHttp(InputStream in, OutputStream out, String firstLine, String target, String method) throws IOException {
        HttpHeaders hdrs = readHttpHeaders(in, firstLine);
        ProxyHandlerHelper.HostAndPort hp = ProxyHandlerHelper.resolveHttpTarget(hdrs.hostHeader, target);
        if (hp == null || hp.host() == null) {
            logger.warn(LocaleUtil.getString("proxy_handler_invalid_target"), clientIp, target);
            sendError(out, 400, "Cannot determine target host");
            return;
        }

        BlockDecision dec = checkBlockedHostOrIp(hp.host());
        if (dec.isBlocked()) {
            logger.info(LocaleUtil.getString("proxy_handler_http_blocked"),
                    clientIp, hp.host(), hp.port(), dec.getReason());
            sendError(out, 403, "Forbidden"); return;
        }

        // ✅ П.6 + П.29: Проверка размера body до чтения (убрана дублирующая проверка после)
        if (hdrs.contentLength > maxBodyBytes) {
            logger.info(LocaleUtil.getString("proxy_handler_http_body_too_large"),
                    clientIp, hdrs.contentLength, maxBodyBytes);
            sendError(out, 413, "Payload Too Large");
            return;
        }

        // ✅ П.6 + П.26: Потоковая передача body без загрузки в память
        byte[] smallBody = null;
        boolean streamLargeBody = false;

        if (hdrs.contentLength > 0) {
            if (hdrs.contentLength <= streamBodyThreshold) {
                // Маленькое body - читаем в byte[] (не в String!)
                smallBody = new byte[(int) hdrs.contentLength];
                int total = 0;
                while (total < smallBody.length) {
                    int r = in.read(smallBody, total, smallBody.length - total);
                    if (r == -1) break;
                    total += r;
                }
                logger.debug(LocaleUtil.getString("proxy_handler_body_read_complete"),
                        clientIp, total);
            } else {
                // ✅ П.26: Большое body - потоковая передача без чтения в память
                streamLargeBody = true;
                logger.info(LocaleUtil.getString("proxy_handler_body_streaming"),
                        clientIp, hdrs.contentLength);
            }
        }

        // ✅ П.26: Для LLM anomaly detector читаем body в память только если маленькое
        String bodyForAnalyzer = null;
        if (smallBody != null && httpAnomalyDetector != null && httpAnomalyDetector.isEnabled()) {
            bodyForAnalyzer = new String(smallBody, StandardCharsets.UTF_8);
        }

        if (httpAnomalyDetector != null && httpAnomalyDetector.isEnabled())
            httpAnomalyDetector.recordRequest(clientIp, method, hp.host(), hp.port(),
                    ProxyHandlerHelper.extractHttpPath(target), hdrs.rawHeaders, bodyForAnalyzer);

        if (hdrs.expectContinuePresent) {
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

            // ✅ П.26: Передаём body без конвертации в String
            if (smallBody != null && smallBody.length > 0) {
                rOut.write(smallBody);
            } else if (streamLargeBody) {
                // ✅ П.26: Потоковая передача большого body
                if (hdrs.chunked) {
                    ProxyHandlerHelper.relayChunked(in, rOut, maxBodyBytes);
                } else {
                    ProxyHandlerHelper.relayFixed(in, rOut, hdrs.contentLength);
                }
            }
            rOut.flush();
            relayResponse(rIn, out);
        } catch (SocketTimeoutException e) {
            logger.info(LocaleUtil.getString("proxy_handler_http_upstream_timeout"),
                    clientIp, hp.host(), hp.port());
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

    /**
     * ✅ П.21: Security Headers для защиты от XSS и clickjacking
     */
    private void sendError(OutputStream out, int code, String msg) throws IOException {
        String body = "<h1>" + code + " " + msg + "</h1>";

        // ✅ П.21: Security Headers
        StringBuilder resp = new StringBuilder();
        resp.append("HTTP/1.1 ").append(code).append(" ").append(msg).append("\r\n");
        resp.append("Content-Type: text/html; charset=UTF-8\r\n");
        resp.append("Content-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
        resp.append("Connection: close\r\n");

        // ✅ П.21: Security Headers для защиты от XSS и clickjacking
        resp.append("X-Content-Type-Options: nosniff\r\n");
        resp.append("X-Frame-Options: DENY\r\n");
        resp.append("X-XSS-Protection: 1; mode=block\r\n");
        resp.append("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n");
        resp.append("Referrer-Policy: no-referrer\r\n");
        resp.append("Cache-Control: no-store, no-cache, must-revalidate\r\n");

        resp.append("\r\n");
        resp.append(body);

        out.write(resp.toString().getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private void closeQuietly(Socket s) {
        if (s == null) return;
        try { s.close(); } catch (IOException e) { logger.trace("Socket close error: {}", e.getMessage()); }
    }

    private record HttpHeaders(String rawHeaders, String hostHeader, long contentLength, boolean chunked,
                               boolean expectContinuePresent) {
    }
}