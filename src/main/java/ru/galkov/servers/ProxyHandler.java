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
import java.util.concurrent.atomic.LongAdder;

import static ru.galkov.Main.getConfig;
import static ru.galkov.util.IoUtil.closeQuietly;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class ProxyHandler implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(ProxyHandler.class);

    private final ConnectionLease lease;
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

    private final LongAdder emptyRequestCounter = new LongAdder();
    private final LongAdder invalidTargetCounter = new LongAdder();
    private final LongAdder unsupportedMethodCounter = new LongAdder();
    private final LongAdder headersTooLargeCounter = new LongAdder();
    private final LongAdder timeoutCounter = new LongAdder();
    private final LongAdder socketErrorCounter = new LongAdder();
    private final LongAdder ioErrorCounter = new LongAdder();

    public ProxyHandler(ConnectionLease lease, BlacklistLoader blacklist, HttpAnomalyDetector detector) {
        this.lease = java.util.Objects.requireNonNull(lease, "lease");
        this.clientSocket = lease.socket();
        this.clientIp = lease.clientIp();
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
        if (!lease.tryStart()) {
            lease.release();
            return;
        }

        try {
            if (lease.isReleased()) return;
            clientSocket.setSoTimeout(clientReadTimeout);
            InputStream in = clientSocket.getInputStream();
            OutputStream out = clientSocket.getOutputStream();
            String firstLine = ProxyHandlerHelper.readLine(in, maxHeaderBytes);
            if (lease.isReleased()) return;
            if (firstLine == null || firstLine.isEmpty()) {
                emptyRequestCounter.increment();
                return;
            }
            if (logger.isTraceEnabled()) logger.trace("{} -> {}", clientIp, firstLine);
            StringTokenizer t = new StringTokenizer(firstLine);
            if (!t.hasMoreTokens()) { invalidTargetCounter.increment(); sendError(out, 400, "Bad Request"); return; }
            String method = t.nextToken().toUpperCase(Locale.ROOT);
            if (!t.hasMoreTokens()) { invalidTargetCounter.increment(); sendError(out, 400, "Bad Request (no target)"); return; }
            String target = t.nextToken();
            if ("CONNECT".equals(method)) { handleConnect(in, out, target); return; }
            if ("GET".equals(method) || "POST".equals(method) || "HEAD".equals(method)
                    || "PUT".equals(method) || "DELETE".equals(method)) {
                handleHttp(in, out, firstLine, target, method);
                return;
            }
            unsupportedMethodCounter.increment();
            sendError(out, 501, "Not Implemented");
        } catch (ProxyHandlerHelper.RequestTooLargeException e) {
            headersTooLargeCounter.increment();
            sendErrorQuietly(431, "Request Header Fields Too Large");
        } catch (SocketTimeoutException e) {
            timeoutCounter.increment();
            sendErrorQuietly(408, "Request Timeout");
        } catch (IOException e) {
            if (e instanceof java.net.SocketException) socketErrorCounter.increment();
            else ioErrorCounter.increment();
        } catch (Throwable t) {
            logger.error(LocaleUtil.getString("proxy_handler_unexpected_error"), clientIp, t);
        } finally {
            logRequestSummary();
            lease.release();
        }
    }

    private boolean released() {
        return lease.isReleased() || clientSocket.isClosed();
    }

    private void validateLimits() {
        if (connectTimeout <= 0 || clientReadTimeout <= 0 || remoteReadTimeout <= 0) throw new IllegalArgumentException("Timeouts must be > 0");
        if (maxHeaderBytes < 1024) throw new IllegalArgumentException("max-header-bytes >= 1024");
        if (maxBodyBytes < 0) throw new IllegalArgumentException("max-body-bytes >= 0");
        if (maxResponseBytes < 0) throw new IllegalArgumentException("max-response-bytes >= 0");
    }

    private void handleConnect(InputStream in, OutputStream out, String target) throws IOException {
        if (released()) return;
        readAndDiscardHeaders(in);
        if (released()) return;
        HostNormalizer.HostAndPort hp = HostNormalizer.parseHostPort(target);
        if (hp == null || hp.host() == null) { invalidTargetCounter.increment(); sendError(out, 400, "Bad Request (invalid host and port)"); return; }
        BlockDecision decision = checkBlockedHostOrIp(hp.host());
        if (decision.isBlocked()) { logger.info(LocaleUtil.getString("proxy_handler_connect_blocked"), clientIp, hp.host(), hp.port(), decision.getReason()); sendError(out, 403, "Forbidden"); return; }
        Socket remote = null;
        try {
            remote = new Socket();
            remote.connect(new InetSocketAddress(hp.host(), hp.port()), connectTimeout);
            if (released()) { closeQuietly(remote); return; }
            remote.setSoTimeout(remoteReadTimeout);
            remote.setTcpNoDelay(true);
            clientSocket.setTcpNoDelay(true);
            out.write("HTTP/1.1 200 Connection established\r\nProxy-Agent: MyProxy\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            byte[] hello = ProxyHandlerHelper.readInitialTlsHandshake(in, clientSocket, clientReadTimeout);
            if (hello == null || released()) { closeQuietly(remote); return; }
            String sni = ProxyHandlerHelper.extractSniFromTlsHandshake(hello);
            if (sni == null || sni.isEmpty()) { closeQuietly(remote); return; }
            if (released()) { closeQuietly(remote); return; }
            BlacklistSnapshot snapshot = blacklist.snapshot();
            BlockDecision sniDecision = snapshot.checkDomain(sni);
            if (sniDecision.isBlocked()) { closeQuietly(remote); return; }
            String normalizedHost = HostNormalizer.normalizeHost(hp.host());
            String normalizedSni = HostNormalizer.normalizeHost(sni);
            boolean mismatch = normalizedHost != null && normalizedSni != null && !normalizedHost.equals(normalizedSni);
            if (mismatch && blockOnSniMismatch) { closeQuietly(remote); return; }
            if (httpAnomalyDetector != null && httpAnomalyDetector.isEnabled()) httpAnomalyDetector.recordRequest(clientIp, "CONNECT", sni, hp.port(), "/", "", null);
            remote.getOutputStream().write(hello);
            remote.getOutputStream().flush();
            ProxyHandlerHelper.runTunnel(clientSocket, remote);
            remote = null;
        } catch (SocketTimeoutException e) {
            closeQuietly(remote);
            if (!released()) sendError(out, 504, "Gateway Timeout");
        } catch (IOException e) {
            closeQuietly(remote);
            if (!released()) sendError(out, 502, "Bad Gateway");
        }
    }

    private void handleHttp(InputStream in, OutputStream out, String firstLine, String target, String method) throws IOException {
        if (released()) return;
        HttpHeaders hdrs = readHttpHeaders(in, firstLine);
        if (released()) return;
        HostNormalizer.HostAndPort hp = ProxyHandlerHelper.resolveHttpTarget(hdrs.hostHeader, target);
        if (hp == null || hp.host() == null) { invalidTargetCounter.increment(); sendError(out, 400, "Cannot determine target host"); return; }
        BlockDecision dec = checkBlockedHostOrIp(hp.host());
        if (dec.isBlocked()) { logger.info(LocaleUtil.getString("proxy_handler_http_blocked"), clientIp, hp.host(), hp.port(), dec.getReason()); sendError(out, 403, "Forbidden"); return; }
        if (hdrs.contentLength > maxBodyBytes) { sendError(out, 413, "Payload Too Large"); return; }
        if (hdrs.expectContinuePresent) { out.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1)); out.flush(); }
        byte[] smallBody = null;
        boolean streamLargeBody = false;
        if (hdrs.contentLength > 0) {
            if (hdrs.contentLength <= streamBodyThreshold) {
                smallBody = new byte[(int) hdrs.contentLength];
                int total = 0;
                while (total < smallBody.length) { int r = in.read(smallBody, total, smallBody.length - total); if (r == -1) break; total += r; }
                if (total < smallBody.length) { sendError(out, 400, "Bad Request (incomplete body)"); return; }
            } else streamLargeBody = true;
        }
        if (released()) return;
        String bodyForAnalyzer = smallBody != null && httpAnomalyDetector != null && httpAnomalyDetector.isEnabled() ? new String(smallBody, StandardCharsets.UTF_8) : null;
        if (httpAnomalyDetector != null && httpAnomalyDetector.isEnabled()) httpAnomalyDetector.recordRequest(clientIp, method, hp.host(), hp.port(), ProxyHandlerHelper.extractHttpPath(target), hdrs.rawHeaders, bodyForAnalyzer);
        try (Socket remote = new Socket()) {
            remote.connect(new InetSocketAddress(hp.host(), hp.port()), connectTimeout);
            if (released()) return;
            remote.setSoTimeout(remoteReadTimeout);
            OutputStream rOut = remote.getOutputStream();
            InputStream rIn = remote.getInputStream();
            String path = ProxyHandlerHelper.extractHttpPath(target);
            rOut.write((method + " " + path + " HTTP/1.1\r\n" + hdrs.rawHeaders).getBytes(StandardCharsets.ISO_8859_1));
            if (smallBody != null && smallBody.length > 0) rOut.write(smallBody);
            else if (streamLargeBody) { if (hdrs.chunked) ProxyHandlerHelper.relayChunked(in, rOut, maxBodyBytes); else ProxyHandlerHelper.relayFixed(in, rOut, hdrs.contentLength); }
            rOut.flush();
            relayResponse(rIn, out);
        } catch (SocketTimeoutException e) {
            if (!released()) sendError(out, 504, "Gateway Timeout");
        }
    }

    private void readAndDiscardHeaders(InputStream in) throws IOException {
        int total = 0;
        String line;
        while ((line = ProxyHandlerHelper.readLine(in, maxHeaderBytes)) != null) {
            total += line.length() + 2;
            if (total > maxHeaderBytes) throw new ProxyHandlerHelper.RequestTooLargeException("CONNECT headers exceed " + maxHeaderBytes + " bytes");
            if (line.isEmpty()) return;
            if (released()) throw new IOException("Connection lease released");
        }
        throw new IOException("Incomplete CONNECT request");
    }

    private BlockDecision checkBlockedHostOrIp(String host) {
        if (blacklist == null || host == null) return BlockDecision.allow();
        BlacklistSnapshot snapshot = blacklist.snapshot();
        BlockDecision ip = snapshot.checkIp(host);
        return ip.isBlocked() ? ip : snapshot.checkDomain(host);
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
            else if (low.startsWith("content-length:")) { Long v = parseContentLength(line.substring(15).trim()); if (v == null) throw new IOException("Invalid Content-Length"); if (contentLen != null && contentLen.longValue() != v.longValue()) throw new IOException("Conflicting Content-Length"); contentLen = v; }
            else if (low.startsWith("transfer-encoding:") && line.substring(18).trim().toLowerCase(Locale.ROOT).contains("chunked")) chunked = true;
            else if (low.startsWith("expect:") && low.substring(7).trim().equals("100-continue")) expect = true;
            if (released()) throw new IOException("Connection lease released");
        }
        if (line == null) throw new IOException("Incomplete HTTP request headers");
        if (chunked && contentLen != null) throw new IOException("Both Content-Length and Transfer-Encoding present");
        sb.append("\r\n");
        return new HttpHeaders(sb.toString(), host, contentLen == null ? 0L : contentLen, chunked, expect);
    }

    private Long parseContentLength(String value) {
        if (value == null || value.isEmpty()) return null;
        try { long length = Long.parseLong(value); return length < 0 ? null : length; } catch (NumberFormatException e) { return null; }
    }

    private void relayResponse(InputStream in, OutputStream out) throws IOException {
        if (released()) return;
        String status = ProxyHandlerHelper.readLine(in, maxHeaderBytes);
        if (status == null) return;
        ProxyHandlerHelper.writeLine(out, status);
        long contentLen = -1;
        boolean chunked = false;
        String line;
        while ((line = ProxyHandlerHelper.readLine(in, maxHeaderBytes)) != null && !line.isEmpty()) {
            ProxyHandlerHelper.writeLine(out, line);
            String low = line.toLowerCase(Locale.ROOT);
            if (low.startsWith("content-length:")) { Long v = parseContentLength(line.substring(15).trim()); if (v != null) contentLen = v; }
            else if (low.startsWith("transfer-encoding:") && line.substring(18).trim().toLowerCase(Locale.ROOT).contains("chunked")) chunked = true;
            if (released()) return;
        }
        if (line == null) return;
        ProxyHandlerHelper.writeLine(out, "");
        long responseLimit = limitResponseBody ? maxResponseBytes : Long.MAX_VALUE;
        if (chunked) ProxyHandlerHelper.relayChunked(in, out, responseLimit);
        else if (contentLen >= 0) { if (limitResponseBody && contentLen > maxResponseBytes) throw new ProxyHandlerHelper.RequestTooLargeException("Response body exceeds " + maxResponseBytes + " bytes"); ProxyHandlerHelper.relayFixed(in, out, contentLen); }
        else relayUntilEofLimited(in, out, responseLimit);
        out.flush();
    }

    private void relayUntilEofLimited(InputStream in, OutputStream out, long max) throws IOException {
        byte[] buf = new byte[8192];
        long total = 0;
        int len;
        while ((len = in.read(buf)) != -1) { if (released()) return; if (total + len > max) throw new ProxyHandlerHelper.RequestTooLargeException("Response body exceeds " + max + " bytes"); out.write(buf, 0, len); total += len; }
    }

    private void sendErrorQuietly(int code, String message) {
        try { if (!released()) sendError(clientSocket.getOutputStream(), code, message); } catch (IOException ignored) { }
    }

    private void sendError(OutputStream out, int code, String message) throws IOException {
        if (released()) return;
        String body = "<h1>" + code + " " + message + "</h1>";
        String response = "HTTP/1.1 " + code + " " + message + "\r\n" + "Content-Type: text/html; charset=UTF-8\r\n" + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n" + "Connection: close\r\n\r\n" + body;
        out.write(response.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private void logRequestSummary() {
        long empty = emptyRequestCounter.sum();
        long invalid = invalidTargetCounter.sum();
        long unsupported = unsupportedMethodCounter.sum();
        long tooLarge = headersTooLargeCounter.sum();
        long timeouts = timeoutCounter.sum();
        long socketErrors = socketErrorCounter.sum();
        long ioErrors = ioErrorCounter.sum();
        if (empty == 0 && invalid == 0 && unsupported == 0 && tooLarge == 0 && timeouts == 0 && socketErrors == 0 && ioErrors == 0) return;
        logger.debug("ProxyHandler request summary: client={}, emptyRequests={}, invalidTargets={}, unsupportedMethods={}, headersTooLarge={}, timeouts={}, socketErrors={}, ioErrors={}", clientIp, empty, invalid, unsupported, tooLarge, timeouts, socketErrors, ioErrors);
    }

    private record HttpHeaders(String rawHeaders, String hostHeader, long contentLength, boolean chunked, boolean expectContinuePresent) { }
}