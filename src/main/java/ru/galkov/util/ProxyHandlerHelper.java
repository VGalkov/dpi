package ru.galkov.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class ProxyHandlerHelper {

    private static final int MAX_TLS_RECORD = 18432;
    private static final int MAX_TLS_HELLO = 65536;

    public record HostAndPort(String host, int port) {
    }

    public static byte[] readInitialTlsHandshake(InputStream in, Socket socket, int clientReadTimeout) throws IOException {
        int origTimeout = socket.getSoTimeout();
        try {
            socket.setSoTimeout(Math.min(clientReadTimeout, 10000));
            byte[] hdr = readExactly(in, 5);
            if (hdr == null) return null;
            int ct = unsignedByte(hdr[0]), len = unsignedShort(hdr[3], hdr[4]);
            if (len < 1 || len > MAX_TLS_RECORD) return hdr;
            byte[] payload = readExactly(in, len);
            if (payload == null) return hdr;
            ByteArrayOutputStream res = new ByteArrayOutputStream(5 + len);
            res.write(hdr); res.write(payload);
            if (ct != 22) return res.toByteArray();
            int hsLen = getTlsHandshakeLength(payload);
            if (hsLen < 0 || hsLen > MAX_TLS_HELLO) return res.toByteArray();
            int need = 4 + hsLen, have = payload.length;
            while (have < need) {
                byte[] next = readExactly(in, 5);
                if (next == null) break;
                int nct = unsignedByte(next[0]), nlen = unsignedShort(next[3], next[4]);
                if (nlen < 1 || nlen > MAX_TLS_RECORD) { res.write(next); break; }
                byte[] np = readExactly(in, nlen);
                res.write(next);
                if (np == null) break;
                res.write(np);
                if (nct != 22) break;
                have += np.length;
                if (res.size() > MAX_TLS_HELLO + 40) break;
            }
            return res.toByteArray();
        } catch (SocketTimeoutException e) {
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
                int ct = unsignedByte(data[off]), len = unsignedShort(data[off + 3], data[off + 4]);
                off += 5;
                if (len < 0 || off + len > data.length) return null;
                if (ct == 22) hs.write(data, off, len);
                off += len;
            }
            byte[] hello = hs.toByteArray();
            if (hello.length < 4 || unsignedByte(hello[0]) != 1) return null;
            int hsLen = unsignedMedium(hello[1], hello[2], hello[3]);
            if (hsLen < 0 || hsLen + 4 > hello.length) return null;
            int pos = 4, end = 4 + hsLen;
            if (pos + 34 > end) return null;
            pos += 2 + 32;
            if (pos + 1 > end) return null;
            int sidLen = unsignedByte(hello[pos]); pos++;
            if (pos + sidLen > end) return null;
            pos += sidLen;
            if (pos + 2 > end) return null;
            int csLen = unsignedShort(hello[pos], hello[pos + 1]); pos += 2;
            if (pos + csLen > end) return null;
            pos += csLen;
            if (pos + 1 > end) return null;
            int cmLen = unsignedByte(hello[pos]); pos++;
            if (pos + cmLen > end) return null;
            pos += cmLen;
            if (pos == end || pos + 2 > end) return null;
            int extLen = unsignedShort(hello[pos], hello[pos + 1]); pos += 2;
            int extEnd = pos + extLen;
            if (extEnd > end) return null;
            while (pos + 4 <= extEnd) {
                int extType = unsignedShort(hello[pos], hello[pos + 1]), extL = unsignedShort(hello[pos + 2], hello[pos + 3]);
                pos += 4;
                if (pos + extL > extEnd) return null;
                if (extType == 0) return extractServerName(hello, pos, extL);
                pos += extL;
            }
            return null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String extractServerName(byte[] hello, int off, int len) {
        if (len < 2 || off + len > hello.length) return null;
        int listLen = unsignedShort(hello[off], hello[off + 1]), pos = off + 2, end = pos + listLen;
        if (end > off + len) return null;
        while (pos + 3 <= end) {
            int nt = unsignedByte(hello[pos]), nl = unsignedShort(hello[pos + 1], hello[pos + 2]);
            pos += 3;
            if (pos + nl > end) return null;
            if (nt == 0 && nl > 0) return HostNormalizer.normalizeHost(new String(hello, pos, nl, StandardCharsets.US_ASCII));
            pos += nl;
        }
        return null;
    }

    private static int getTlsHandshakeLength(byte[] p) {
        if (p == null || p.length < 4 || unsignedByte(p[0]) != 1) return -1;
        return unsignedMedium(p[1], p[2], p[3]);
    }

    private static byte[] readExactly(InputStream in, int len) throws IOException {
        byte[] buf = new byte[len];
        int total = 0;
        while (total < len) {
            int r = in.read(buf, total, len - total);
            if (r == -1) return null;
            total += r;
        }
        return buf;
    }

    public static HostAndPort parseConnectTarget(String target) {
        if (target == null || target.isEmpty()) return null;
        String host, portText;
        if (target.startsWith("[")) {
            int close = target.indexOf(']');
            if (close <= 1 || close + 1 >= target.length() || target.charAt(close + 1) != ':') return null;
            host = target.substring(1, close);
            portText = target.substring(close + 2);
        } else {
            int colon = target.lastIndexOf(':');
            if (colon <= 0 || colon == target.length() - 1) return null;
            host = target.substring(0, colon);
            portText = target.substring(colon + 1);
            if (host.indexOf(':') >= 0) return null;
        }
        int port;
        try { port = Integer.parseInt(portText); } catch (NumberFormatException e) { return null; }
        if (port < 1 || port > 65535) return null;
        return new HostAndPort(host, port);
    }

    public static HostAndPort resolveHttpTarget(String hostHeader, String target) {
        try {
            if (hostHeader != null && !hostHeader.isEmpty()) return parseHttpHostHeader(hostHeader);
            if (target.startsWith("http://") || target.startsWith("https://")) {
                URL url = new URL(target);
                String host = url.getHost();
                if (host == null || host.isEmpty()) return null;
                int port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
                if (port < 1 || port > 65535) return null;
                return new HostAndPort(host, port);
            }
            return null;
        } catch (Exception e) { return null; }
    }

    private static HostAndPort parseHttpHostHeader(String h) {
        if (h == null || h.isEmpty()) return null;
        if (h.startsWith("[")) {
            int close = h.indexOf(']');
            if (close <= 1) return null;
            String host = h.substring(1, close);
            if (close == h.length() - 1) return new HostAndPort(host, 80);
            if (h.charAt(close + 1) != ':') return null;
            try {
                int port = Integer.parseInt(h.substring(close + 2));
                if (port < 1 || port > 65535) return null;
                return new HostAndPort(host, port);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        int colon = h.lastIndexOf(':');
        if (colon < 0) return new HostAndPort(h, 80);
        String host = h.substring(0, colon);
        try {
            int port = Integer.parseInt(h.substring(colon + 1));
            if (host.isEmpty() || port < 1 || port > 65535) return null;
            return new HostAndPort(host, port);
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
            return "/";
        }
    }

    public static void runTunnel(Socket client, Socket remote) {
        Thread t1 = new Thread(() -> pipe(client, remote), "Proxy-Tunnel-ClientToRemote");
        Thread t2 = new Thread(() -> pipe(remote, client), "Proxy-Tunnel-RemoteToClient");
        t1.setDaemon(true); t2.setDaemon(true);
        t1.start(); t2.start();
        try { t1.join(); t2.join(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        finally { closeQuietly(client); closeQuietly(remote); }
    }

    private static void pipe(Socket src, Socket dst) {
        if (src == null || dst == null) return;
        byte[] buf = new byte[8192];
        try {
            InputStream in = src.getInputStream();
            OutputStream out = dst.getOutputStream();
            int len;
            while ((len = in.read(buf)) != -1) { out.write(buf, 0, len); out.flush(); }
        } catch (IOException e) {  }
    }

    public static String readLine(InputStream in, int max) throws IOException {
        StringBuilder sb = null;
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                if (sb != null && !sb.isEmpty() && sb.charAt(sb.length() - 1) == '\r')
                    sb.setLength(sb.length() - 1);
                return sb == null ? "" : sb.toString();
            }
            if (sb == null) sb = new StringBuilder();
            if (sb.length() >= max) throw new RequestTooLargeException("Line exceeds " + max + " bytes");
            sb.append((char) b);
        }
        return sb == null ? null : sb.toString();
    }

    public static void writeLine(OutputStream out, String line) throws IOException {
        out.write(line.getBytes(StandardCharsets.ISO_8859_1));
        out.write('\r'); out.write('\n');
    }

    public static void relayChunked(InputStream in, OutputStream out, long maxBodyBytes) throws IOException {
        byte[] buf = new byte[8192];
        long total = 0;
        while (true) {
            String chunkLine = readLine(in, 64);
            if (chunkLine == null) throw new IOException("Unexpected end of chunked body");
            int semi = chunkLine.indexOf(';');
            String sizePart = semi >= 0 ? chunkLine.substring(0, semi).trim() : chunkLine.trim();
            int chunkSize;
            try { chunkSize = Integer.parseInt(sizePart, 16); } catch (NumberFormatException e) { throw new IOException("Invalid chunk size: " + sizePart); }
            if (chunkSize < 0) throw new IOException("Negative chunk size: " + chunkSize);
            if (chunkSize == 0) break;
            if (total + chunkSize > maxBodyBytes) throw new RequestTooLargeException("Chunked body exceeds " + maxBodyBytes + " bytes");
            int rem = chunkSize;
            while (rem > 0) { int r = in.read(buf, 0, Math.min(rem, buf.length)); if (r == -1) throw new IOException("Unexpected end of chunked body"); out.write(buf, 0, r); rem -= r; }
            total += chunkSize;
            readLine(in, 2);
        }
    }

    public static void relayFixed(InputStream in, OutputStream out, long len) throws IOException {
        byte[] buf = new byte[8192];
        long rem = len;
        while (rem > 0) { int r = in.read(buf, 0, (int) Math.min(rem, buf.length)); if (r == -1) throw new IOException("Unexpected end of body"); out.write(buf, 0, r); rem -= r; }
    }

    public static void relayUntilEof(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int len;
        while ((len = in.read(buf)) != -1) out.write(buf, 0, len);
    }

    private static int unsignedByte(byte v) { return v & 0xFF; }
    private static int unsignedShort(byte a, byte b) { return ((a & 0xFF) << 8) | (b & 0xFF); }
    private static int unsignedMedium(byte a, byte b, byte c) { return ((a & 0xFF) << 16) | ((b & 0xFF) << 8) | (c & 0xFF); }

    private static void closeQuietly(Socket s) {
        if (s == null) return;
        try { s.close(); } catch (IOException ignored) {}
    }

    public static final class RequestTooLargeException extends IOException {
        public RequestTooLargeException(String msg) { super(msg); }
    }
}