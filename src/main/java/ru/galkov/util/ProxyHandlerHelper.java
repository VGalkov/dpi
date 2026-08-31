package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import static ru.galkov.util.IoUtil.readExactly;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class ProxyHandlerHelper {

    private static final Logger logger = LoggerFactory.getLogger(ProxyHandlerHelper.class);

    private static final int MAX_TLS_RECORD = 18432;
    private static final int MAX_TLS_HELLO = 65536;

    private ProxyHandlerHelper() {
    }

    public static byte[] readInitialTlsHandshake(InputStream in, Socket socket, int clientReadTimeout) throws IOException {
        int origTimeout = socket.getSoTimeout();
        try {
            socket.setSoTimeout(Math.min(clientReadTimeout, 10000));
            byte[] hdr = readExactly(in, 5);
            if (hdr == null) return null;
            int contentType = hdr[0] & 0xFF;
            int recordLen = ((hdr[3] & 0xFF) << 8) | (hdr[4] & 0xFF);
            if (recordLen < 1 || recordLen > MAX_TLS_RECORD) return hdr;
            byte[] payload = readExactly(in, recordLen);
            if (payload == null) return hdr;
            ByteArrayOutputStream res = new ByteArrayOutputStream(5 + recordLen);
            res.write(hdr);
            res.write(payload);
            if (contentType != 22) return res.toByteArray();
            int handshakeLen = (payload.length < 4 || (payload[0] & 0xFF) != 1) ? -1
                    : ((payload[1] & 0xFF) << 16) | ((payload[2] & 0xFF) << 8) | (payload[3] & 0xFF);
            if (handshakeLen < 0 || handshakeLen > MAX_TLS_HELLO) return res.toByteArray();
            int need = 4 + handshakeLen;
            int have = payload.length;
            while (have < need) {
                if (res.size() > MAX_TLS_HELLO + 40) break;
                byte[] nextHdr = readExactly(in, 5);
                if (nextHdr == null) break;
                int nextContentType = nextHdr[0] & 0xFF;
                int nextLen = ((nextHdr[3] & 0xFF) << 8) | (nextHdr[4] & 0xFF);
                if (nextLen < 1 || nextLen > MAX_TLS_RECORD) {
                    res.write(nextHdr);
                    break;
                }
                byte[] nextPayload = readExactly(in, nextLen);
                res.write(nextHdr);
                if (nextPayload == null) break;
                res.write(nextPayload);
                if (nextContentType == 22) {
                    have += nextPayload.length;
                    if (have >= need) break;
                } else {
                    break;
                }
            }
            return res.toByteArray();
        } catch (SocketTimeoutException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Timeout while reading initial TLS handshake");
            }
            return null;
        } finally {
            socket.setSoTimeout(origTimeout);
        }
    }

    public static String extractSniFromTlsHandshake(byte[] data) {
        if (data == null || data.length < 9) return null;
        try {
            int off = 0;
            ByteArrayOutputStream hs = new ByteArrayOutputStream();
            while (off + 5 <= data.length) {
                int ct = data[off] & 0xFF;
                int len = ((data[off + 3] & 0xFF) << 8) | (data[off + 4] & 0xFF);
                off += 5;
                if (off + len > data.length) return null;
                if (ct == 22) hs.write(data, off, len);
                off += len;
            }
            byte[] hello = hs.toByteArray();
            if (hello.length < 4 || (hello[0] & 0xFF) != 1) return null;
            int hsLen = ((hello[1] & 0xFF) << 16) | ((hello[2] & 0xFF) << 8) | (hello[3] & 0xFF);
            if (hsLen + 4 > hello.length) return null;
            int pos = 4, end = 4 + hsLen;
            if (pos + 34 > end) return null;
            pos += 2 + 32;
            if (pos + 1 > end) return null;
            int sidLen = hello[pos] & 0xFF;
            pos++;
            if (pos + sidLen > end) return null;
            pos += sidLen;
            if (pos + 2 > end) return null;
            int csLen = ((hello[pos] & 0xFF) << 8) | (hello[pos + 1] & 0xFF);
            pos += 2;
            if (pos + csLen > end) return null;
            pos += csLen;
            if (pos + 1 > end) return null;
            int cmLen = hello[pos] & 0xFF;
            pos++;
            if (pos + cmLen > end) return null;
            pos += cmLen;
            if (pos == end || pos + 2 > end) return null;
            int extLen = ((hello[pos] & 0xFF) << 8) | (hello[pos + 1] & 0xFF);
            pos += 2;
            int extEnd = pos + extLen;
            if (extEnd > end) return null;
            while (pos + 4 <= extEnd) {
                int extType = ((hello[pos] & 0xFF) << 8) | (hello[pos + 1] & 0xFF);
                int extL = ((hello[pos + 2] & 0xFF) << 8) | (hello[pos + 3] & 0xFF);
                pos += 4;
                if (pos + extL > extEnd) return null;
                if (extType == 0) return extractServerName(hello, pos, extL);
                pos += extL;
            }
            return null;
        } catch (RuntimeException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Invalid TLS handshake structure", e);
            }
            return null;
        }
    }

    private static String extractServerName(byte[] hello, int off, int len) {
        if (len < 2 || off + len > hello.length) return null;
        int listLen = ((hello[off] & 0xFF) << 8) | (hello[off + 1] & 0xFF);
        int pos = off + 2, end = pos + listLen;
        if (end > off + len) return null;
        while (pos + 3 <= end) {
            int nt = hello[pos] & 0xFF;
            int nl = ((hello[pos + 1] & 0xFF) << 8) | (hello[pos + 2] & 0xFF);
            pos += 3;
            if (pos + nl > end) return null;
            if (nt == 0 && nl > 0)
                return HostNormalizer.normalizeHost(new String(hello, pos, nl, StandardCharsets.US_ASCII));
            pos += nl;
        }
        return null;
    }

    public static HostNormalizer.HostAndPort resolveHttpTarget(String hostHeader, String target) {
        try {
            if (hostHeader != null && !hostHeader.isEmpty()) {
                return parseHttpHostHeader(hostHeader);
            }
            if (target.startsWith("http://") || target.startsWith("https://")) {
                URL url = new URL(target);
                String host = url.getHost();
                if (host == null || host.isEmpty()) return null;
                int port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
                if (port < 1 || port > 65535) return null;
                return new HostNormalizer.HostAndPort(host, port);
            }
            return null;
        } catch (Exception e) {
            if (logger.isDebugEnabled()) logger.debug("Unable to resolve HTTP target", e);

            return null;
        }
    }

    public static HostNormalizer.HostAndPort parseHttpHostHeader(String h) {
        if (h == null || h.isEmpty()) return null;
        if (h.startsWith("[")) {
            int close = h.indexOf(']');
            if (close <= 1) return null;
            String host = h.substring(1, close);
            if (close == h.length() - 1) return new HostNormalizer.HostAndPort(host, 80);
            if (h.charAt(close + 1) != ':') return null;
            try {
                int port = Integer.parseInt(h.substring(close + 2));
                if (port < 1 || port > 65535) return null;
                return new HostNormalizer.HostAndPort(host, port);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        int colon = h.lastIndexOf(':');
        if (colon < 0) return new HostNormalizer.HostAndPort(h, 80);
        String host = h.substring(0, colon);
        try {
            int port = Integer.parseInt(h.substring(colon + 1));
            if (host.isEmpty() || port < 1 || port > 65535) return null;
            return new HostNormalizer.HostAndPort(host, port);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static String extractHttpPath(String target) {
        if (target == null) return "/";
        if (!target.startsWith("http://") && !target.startsWith("https://")) return target;
        try {
            URL url = new URL(target);
            String path = url.getPath();
            if (path == null || path.isEmpty()) path = "/";
            if (url.getQuery() != null) path += "?" + url.getQuery();
            return path;
        } catch (Exception e) {
            if (logger.isDebugEnabled()) logger.debug("Unable to extract HTTP path", e);

            return "/";
        }
    }

    public static void runTunnel(Socket client, Socket remote) {
        Thread t1 = new Thread(() -> pipe(client, remote), "Proxy-Tunnel-ClientToRemote");
        Thread t2 = new Thread(() -> pipe(remote, client), "Proxy-Tunnel-RemoteToClient");
        t1.setDaemon(true);
        t2.setDaemon(true);
        t1.start();
        t2.start();
        try {
            t1.join();
            if (!t1.isAlive()) IoUtil.closeQuietly(remote);
            t2.join(30000);
            if (t2.isAlive()) t2.interrupt();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            t1.interrupt();
            t2.interrupt();
            if (logger.isDebugEnabled()) logger.debug("Proxy tunnel interrupted", e);

        } finally {
            IoUtil.closeQuietly(client);
            IoUtil.closeQuietly(remote);
        }
    }

    private static void pipe(Socket src, Socket dst) {
        if (src == null || dst == null) return;
        byte[] buf = new byte[8192];
        InputStream in = null;
        OutputStream out = null;
        try {
            in = src.getInputStream();
            out = dst.getOutputStream();
            int len;
            while ((len = in.read(buf)) != -1) {
                out.write(buf, 0, len);
            }
            try {
                dst.shutdownOutput();
            } catch (IOException ignored) {
            }
        } catch (IOException e) {
            if (logger.isDebugEnabled()) logger.debug("Proxy tunnel pipe closed: {}", e.getMessage());

        } finally {
            if (in != null) {
                try { IoUtil.closeQuietly(src); } catch (Exception ignored) {}
            }
            if (out != null) {
                try { IoUtil.closeQuietly(dst); } catch (Exception ignored) {}
            }
        }
    }

    public static String readLine(InputStream in, int max) throws IOException {
        byte[] buf = new byte[max];
        int pos = 0;
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                int len = (pos > 0 && buf[pos - 1] == '\r') ? pos - 1 : pos;
                return new String(buf, 0, len, StandardCharsets.ISO_8859_1);
            }
            if (pos >= max) throw new RequestTooLargeException("Line exceeds " + max + " bytes");
            buf[pos++] = (byte) b;
        }
        return pos == 0 ? null : new String(buf, 0, pos, StandardCharsets.ISO_8859_1);
    }

    public static void writeLine(OutputStream out, String line) throws IOException {
        out.write(line.getBytes(StandardCharsets.ISO_8859_1));
        out.write('\r');
        out.write('\n');
    }

    public static void relayChunked(InputStream in, OutputStream out, long maxBodyBytes) throws IOException {
        if (in == null || out == null) {
            throw new IllegalArgumentException("in and out must not be null");
        }
        byte[] buf = new byte[8192];
        long total = 0;
        while (true) {
            String chunkLine = readLine(in, 64);
            if (chunkLine == null) throw new IOException("Unexpected end of chunked body");
            int semi = chunkLine.indexOf(';');
            String sizePart = semi >= 0 ? chunkLine.substring(0, semi).trim() : chunkLine.trim();
            int chunkSize;
            try {
                chunkSize = Integer.parseInt(sizePart, 16);
            } catch (NumberFormatException e) {
                throw new IOException("Invalid chunk size: " + sizePart);
            }
            if (chunkSize < 0) throw new IOException("Negative chunk size: " + chunkSize);
            if (chunkSize == 0) break;
            if (total + chunkSize > maxBodyBytes)
                throw new RequestTooLargeException("Chunked body exceeds " + maxBodyBytes + " bytes");
            int rem = chunkSize;
            while (rem > 0) {
                int r = in.read(buf, 0, Math.min(rem, buf.length));
                if (r == -1) throw new IOException("Unexpected end of chunked body");
                out.write(buf, 0, r);
                rem -= r;
            }
            total += chunkSize;
            readLine(in, 2);
        }
    }

    public static void relayFixed(InputStream in, OutputStream out, long len) throws IOException {
        if (in == null || out == null) {
            throw new IllegalArgumentException("in and out must not be null");
        }
        byte[] buf = new byte[8192];
        long rem = len;
        while (rem > 0) {
            int r = in.read(buf, 0, (int) Math.min(rem, buf.length));
            if (r == -1) throw new IOException("Unexpected end of body");
            out.write(buf, 0, r);
            rem -= r;
        }
    }


    public static StringBuilder readHeaders(
            InputStream in,
            int maxHeaderBytes,
            boolean discardOnly,
            String firstLine,
            java.util.function.BooleanSupplier releasedChecker
    ) throws IOException {
        StringBuilder sb = discardOnly ? null : new StringBuilder(firstLine).append("\r\n");
        int total = firstLine.length() + 2;
        String line;
        while ((line = readLine(in, maxHeaderBytes)) != null && !line.isEmpty()) {
            total += line.length() + 2;
            if (total > maxHeaderBytes) {
                throw new RequestTooLargeException(
                        discardOnly
                                ? "CONNECT headers exceed " + maxHeaderBytes + " bytes"
                                : "HTTP headers exceed " + maxHeaderBytes + " bytes"
                );
            }
            if (!discardOnly) sb.append(line).append("\r\n");
            if (releasedChecker.getAsBoolean()) throw new IOException("Connection lease released");

        }
        if (line == null) {
            throw new IOException(discardOnly ? "Incomplete CONNECT request" : "Incomplete HTTP request headers");
        }
        if (!discardOnly) sb.append("\r\n");
        return sb;
    }

    public static final class RequestTooLargeException extends IOException {
        public RequestTooLargeException(String msg) { super(msg); }
    }
}