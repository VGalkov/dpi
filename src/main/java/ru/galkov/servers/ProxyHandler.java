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
import static ru.galkov.util.IoUtil.closeQuietly;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public class ProxyHandler implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(ProxyHandler.class);
    private final Socket clientSocket;
    private final String clientIp;
    private final BlacklistLoader blacklist;
    private final int connectTimeout, clientReadTimeout, remoteReadTimeout, maxHeaderBytes;
    private final long maxBodyBytes;
    private final long streamBodyThreshold;
    private final HttpAnomalyDetector httpAnomalyDetector;
    private final boolean blockOnSniMismatch;
    private final boolean limitResponseBody;
    private final long maxResponseBytes;

    public ProxyHandler(Socket clientSocket, String clientIp, BlacklistLoader blacklist, HttpAnomalyDetector detector) {
        this.clientSocket = clientSocket;
        this.clientIp = clientIp != null ? clientIp : "unknown";
        this.blacklist = blacklist;
        this.httpAnomalyDetector = detector;
        this.connectTimeout = getConfig().getInt("proxy.connect-timeout-millis");
        this.clientReadTimeout = getConfig().getInt("proxy.client-read-timeout-millis");
        this.remoteReadTimeout = getConfig().getInt("proxy.remote-read-timeout-millis");
        this.maxHeaderBytes = getConfig().getInt("proxy.max-header-bytes");
        this.maxBodyBytes = getConfig().getLong("proxy.max-body-bytes");
        this.streamBodyThreshold = getConfig().getLong("proxy.stream-body-threshold");
        this.blockOnSniMismatch = getConfig().getBoolean("proxy.block-on-sni-mismatch");
        this.limitResponseBody = getConfig().getBoolean("proxy.limit-response-body");
        this.maxResponseBytes = getConfig().getLong("proxy.max-response-bytes");
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
        if (maxResponseBytes < 0) throw new IllegalArgumentException("max-response-bytes >= 0");
    }

    private void handleConnect(InputStream in, OutputStream out, String target) throws IOException {
        readAndDiscardHeaders(in);
        HostNormalizer.HostAndPort hp = HostNormalizer.parseHostPort(target);
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

        logger.info("PROXY_CONNECT client={} host={} port={}", clientIp, hp.host(), hp.port());

        Socket remote = null;
        try {
            remote = new Socket();
            remote.connect(new InetSocketAddress(hp.host(), hp.port()), connectTimeout);
            remote.setSoTimeout(remoteReadTimeout);
            remote.setTcpNoDelay(true);
            clientSocket.setTcpNoDelay(true);

            out.write("HTTP/1.1 200 Connection established\r\nProxy-Agent: MyProxy\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            byte[] hello = ProxyHandlerHelper.readInitialTlsHandshake(in, clientSocket, clientReadTimeout);
            if (hello == null) {
                logger.warn("{} -> CONNECT {}:{}: TLS ClientHello not received, closing",
                        clientIp, hp.host(), hp.port());
                closeQuietly(remote);
                return;
            }

            String sni = ProxyHandlerHelper.extractSniFromTlsHandshake(hello);

            if (sni == null || sni.isEmpty()) {
                logger.warn("{} -> CONNECT {}:{}: SNI not extractable, closing (fail-closed)",
                        clientIp, hp.host(), hp.port());
                closeQuietly(remote);
                return;
            }

            logger.info("{} -> CONNECT {}:{}: SNI={}", clientIp, hp.host(), hp.port(), sni);
            BlacklistSnapshot snapshot = blacklist.snapshot();
            BlockDecision sniDecision = snapshot.checkDomain(sni);
            if (sniDecision.isBlocked()) {
                logger.info("PROXY_CONNECT_BLOCKED client={} sni={} reason={} rule={}",
                        clientIp, sni, "SNI", sniDecision.getMatchedRule());
                closeQuietly(remote); return;
            }

            String normalizedHost = HostNormalizer.normalizeHost(hp.host());
            String normalizedSni = HostNormalizer.normalizeHost(sni);
            boolean mismatch = normalizedHost != null && normalizedSni != null
                    && !normalizedHost.equals(normalizedSni);
            if (mismatch) {
                if (blockOnSniMismatch) {
                    logger.warn("PROXY_CONNECT_SNI_MISMATCH_BLOCKED client={} host={} sni={} action=block",
                            clientIp, hp.host(), sni);
                    closeQuietly(remote);
                    return;
                }
                logger.warn(LocaleUtil.getString("proxy_handler_connect_sni_mismatch"),
                        clientIp, hp.host(), hp.port(), sni);
            }

            if (httpAnomalyDetector != null && httpAnomalyDetector.isEnabled()) {
                httpAnomalyDetector.recordRequest(clientIp, "CONNECT",
                        sni, hp.port(), "/", "", null);
            }

            remote.getOutputStream().write(hello);
            remote.getOutputStream().flush();
            logger.info(LocaleUtil.getString("proxy_handler_connect_established"),
                    clientIp, hp.host(), hp.port());
            ProxyHandlerHelper.runTunnel(clientSocket, remote);
            remote = null;
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

    private void handleHttp(InputStream in, OutputStream out, String firstLine, String target, String method) throws IOException {
        HttpHeaders hdrs = readHttpHeaders(in, firstLine);
        HostNormalizer.HostAndPort hp = ProxyHandlerHelper.resolveHttpTarget(hdrs.hostHeader, target);
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

        if (hdrs.contentLength > maxBodyBytes) {
            logger.info(LocaleUtil.getString("proxy_handler_http_body_too_large"),
                    clientIp, hdrs.contentLength, maxBodyBytes);
            sendError(out, 413, "Payload Too Large");
            return;
        }

        if (hdrs.expectContinuePresent) {
            out.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
        }

        byte[] smallBody = null;
        boolean streamLargeBody = false;

        if (hdrs.contentLength > 0) {
            if (hdrs.contentLength <= streamBodyThreshold) {
                smallBody = new byte[(int) hdrs.contentLength];
                int total = 0;
                while (total < smallBody.length) {
                    int r = in.read(smallBody, total, smallBody.length - total);
                    if (r == -1) break;
                    total += r;
                }

                if (total < smallBody.length) {
                    logger.warn("{} -> body truncated: expected {}, got {}",
                            clientIp, smallBody.length, total);
                    sendError(out, 400, "Bad Request (incomplete body)");
                    return;
                }

                logger.debug(LocaleUtil.getString("proxy_handler_body_read_complete"),
                        clientIp, total);
            } else {
                streamLargeBody = true;
                logger.info(LocaleUtil.getString("proxy_handler_body_streaming"),
                        clientIp, hdrs.contentLength);
            }
        }

        String bodyForAnalyzer = null;
        if (smallBody != null && httpAnomalyDetector != null && httpAnomalyDetector.isEnabled()) {
            bodyForAnalyzer = new String(smallBody, StandardCharsets.UTF_8);
        }

        if (httpAnomalyDetector != null && httpAnomalyDetector.isEnabled()) {
            String path = ProxyHandlerHelper.extractHttpPath(target);
            httpAnomalyDetector.recordRequest(clientIp, method, hp.host(), hp.port(), path, hdrs.rawHeaders, bodyForAnalyzer);
        }

        try (Socket remote = new Socket()) {
            remote.connect(new InetSocketAddress(hp.host(), hp.port()), connectTimeout);
            remote.setSoTimeout(remoteReadTimeout);
            OutputStream rOut = remote.getOutputStream();
            InputStream rIn = remote.getInputStream();
            String path = ProxyHandlerHelper.extractHttpPath(target);
            String req = method + " " + path + " HTTP/1.1\r\n" + hdrs.rawHeaders;
            rOut.write(req.getBytes(StandardCharsets.ISO_8859_1));

            if (smallBody != null && smallBody.length > 0) {
                rOut.write(smallBody);
            } else if (streamLargeBody) {
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

        if (chunked && contentLen != null) {
            throw new IOException("Both Content-Length and Transfer-Encoding present");
        }

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

        long responseLimit = limitResponseBody ? maxResponseBytes : Long.MAX_VALUE;

        if (chunked) {
            ProxyHandlerHelper.relayChunked(in, out, responseLimit);
        } else if (contentLen >= 0) {
            if (limitResponseBody && contentLen > maxResponseBytes) {
                throw new ProxyHandlerHelper.RequestTooLargeException(
                        "Response body exceeds " + maxResponseBytes + " bytes");
            }
            ProxyHandlerHelper.relayFixed(in, out, contentLen);
        } else {
            relayUntilEofLimited(in, out, responseLimit);
        }
        out.flush();
    }

    private void relayUntilEofLimited(InputStream in, OutputStream out, long max) throws IOException {
        byte[] buf = new byte[8192];
        long total = 0;
        int len;
        while ((len = in.read(buf)) != -1) {
            if (total + len > max) {
                throw new ProxyHandlerHelper.RequestTooLargeException(
                        "Response body exceeds " + max + " bytes");
            }
            out.write(buf, 0, len);
            total += len;
        }
    }

    private void sendErrorQuietly(int code, String msg) {
        try { if (!clientSocket.isClosed()) sendError(clientSocket.getOutputStream(), code, msg); } catch (IOException ignored) {}
    }

    private void sendError(OutputStream out, int code, String msg) throws IOException {
        String body = "<h1>" + code + " " + msg + "</h1>";

        String resp = "HTTP/1.1 " + code + " " + msg + "\r\n" +
                "Content-Type: text/html; charset=UTF-8\r\n" +
                "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n" +
                "Connection: close\r\n" +
                "X-Content-Type-Options: nosniff\r\n" +
                "X-Frame-Options: DENY\r\n" +
                "X-XSS-Protection: 1; mode=block\r\n" +
                "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n" +
                "Referrer-Policy: no-referrer\r\n" +
                "Cache-Control: no-store, no-cache, must-revalidate\r\n" +
                "\r\n" +
                body;

        out.write(resp.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private record HttpHeaders(String rawHeaders, String hostHeader, long contentLength, boolean chunked,
                               boolean expectContinuePresent) {
    }
}