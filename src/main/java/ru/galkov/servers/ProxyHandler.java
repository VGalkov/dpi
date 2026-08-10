package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.StringTokenizer;
import java.io.*;

public class ProxyHandler implements Runnable {
    private final Socket clientSocket;
    private final String clientIp;
    private final BlacklistLoader blacklist;

    private static final Logger logger = LoggerFactory.getLogger(ProxyHandler.class);

    public ProxyHandler(Socket clientSocket, String clientIp, BlacklistLoader blacklist) {
        this.clientSocket = clientSocket;
        this.clientIp = clientIp;
        this.blacklist = blacklist;
    }

    @Override
    public void run() {
        InputStream clientIn = null;
        OutputStream clientOut = null;

        try {
            clientIn = clientSocket.getInputStream();
            clientOut = clientSocket.getOutputStream();

            String firstLine = readLine(clientIn);
            if (firstLine == null || firstLine.isEmpty()) {
                logger.debug("{} -> Empty request", clientIp);
                return;
            }

            logger.trace("{} -> Request: {}", clientIp, firstLine);

            StringTokenizer st = new StringTokenizer(firstLine);
            if (!st.hasMoreTokens()) {
                sendError(clientOut, 400, "Bad Request");
                return;
            }

            String method = st.nextToken().toUpperCase();

            if (!st.hasMoreTokens()) {
                sendError(clientOut, 400, "Bad Request (no target)");
                return;
            }
            String target = st.nextToken();

            if ("CONNECT".equals(method)) {
                handleConnect(clientIn, clientOut, target);
            } else if ("GET".equals(method) || "POST".equals(method)
                    || "HEAD".equals(method) || "PUT".equals(method)
                    || "DELETE".equals(method)) {
                handleHttp(clientIn, clientOut, firstLine, target, method);
            } else {
                sendError(clientOut, 501, "Not Implemented");
            }
        } catch (IOException e) {
            if (!(e instanceof java.net.SocketException)) {
                logger.warn("Network error for client {}: {}", clientIp, e.getMessage());
            }
        } finally {
            try {
                if (clientSocket != null) clientSocket.close();
            } catch (IOException ignored) {}
        }
    }

    private void handleConnect(InputStream clientIn, OutputStream clientOut, String target) throws IOException {
        int colonIndex = target.lastIndexOf(':');
        if (colonIndex == -1) {
            sendError(clientOut, 400, "Bad Request (missing port)");
            return;
        }

        String host = target.substring(0, colonIndex);
        int port;
        try {
            port = Integer.parseInt(target.substring(colonIndex + 1));
        } catch (NumberFormatException e) {
            sendError(clientOut, 400, "Invalid port");
            return;
        }

        logger.info("{} -> CONNECT {}:{}", clientIp, host, port);

        if (blacklist != null && blacklist.isBlocked(host, clientIp)) {
            sendError(clientOut, 403, "Forbidden");
            return;
        }

        Socket remoteSocket;
        try {
            remoteSocket = new Socket(host, port);
        } catch (IOException e) {
            sendError(clientOut, 502, "Bad Gateway");
            logger.error("Failed to connect to {}:{}", host, port, e);
            return;
        }

        String response = "HTTP/1.1 200 Connection established\r\n" +
                "Proxy-Agent: MyProxy\r\n" +
                "\r\n";
        clientOut.write(response.getBytes(StandardCharsets.ISO_8859_1));
        clientOut.flush();

        runTunnel(clientSocket, remoteSocket);

    }

    private void handleHttp(InputStream clientIn, OutputStream clientOut, String firstLine, String target, String method) throws IOException {
        StringBuilder headersBuilder = new StringBuilder();
        headersBuilder.append(firstLine).append("\r\n");

        String line;
        String hostHeader = null;
        long contentLength = -1;

        while ((line = readLine(clientIn)) != null && !line.isEmpty()) {
            headersBuilder.append(line).append("\r\n");

            String lowerLine = line.toLowerCase();
            if (lowerLine.startsWith("host: ")) {
                hostHeader = line.substring(5).trim();
            } else if (lowerLine.startsWith("content-length: ")) {
                try {
                    contentLength = Long.parseLong(line.substring(15).trim());
                } catch (NumberFormatException ignored) {}
            }
        }
        headersBuilder.append("\r\n");

        byte[] body = new byte[0];
        if (contentLength > 0) {
            body = new byte[(int) contentLength];
            int totalRead = 0;
            while (totalRead < contentLength) {
                int read = clientIn.read(body, totalRead, (int) (contentLength - totalRead));
                if (read == -1) break;
                totalRead += read;
            }
        }

        String finalHost = null;
        int finalPort = 80;

        if (hostHeader != null) {
            String[] parts = hostHeader.split(":", 2);
            finalHost = parts[0];
            if (parts.length > 1) {
                finalPort = Integer.parseInt(parts[1]);
            }
        } else {
            java.net.URL url;
            if (target.startsWith("http://") || target.startsWith("https://")) {
                url = new java.net.URL(target);
                finalHost = url.getHost();
                finalPort = (url.getPort() == -1) ? url.getDefaultPort() : url.getPort();
            } else {
                sendError(clientOut, 400, "Missing Host header");
                return;
            }
        }

        if (finalHost == null) {
            sendError(clientOut, 400, "Cannot determine target host");
            return;
        }

        if (blacklist != null && blacklist.isBlocked(finalHost, clientIp)) {
            sendError(clientOut, 403, "Forbidden");
            return;
        }

        Socket remoteSocket;
        try {
            remoteSocket = new Socket(finalHost, finalPort);
        } catch (IOException e) {
            sendError(clientOut, 502, "Bad Gateway");
            return;
        }

        OutputStream remoteOut = remoteSocket.getOutputStream();

        String path = target;
        if (!target.startsWith("http://") && !target.startsWith("https://")) {
            path = target;
        } else {
            java.net.URL url = new java.net.URL(target);
            path = url.getPath();
            if (url.getQuery() != null) path += "?" + url.getQuery();
            if (path.isEmpty()) path = "/";
        }

        String finalRequest = method + " " + path + " HTTP/1.1\r\n" + headersBuilder;

        remoteOut.write(finalRequest.getBytes(StandardCharsets.ISO_8859_1));
        if (body.length > 0) {
            remoteOut.write(body);
        }
        remoteOut.flush();

        InputStream remoteIn = remoteSocket.getInputStream();
        byte[] buffer = new byte[8192];
        int len;
        while ((len = remoteIn.read(buffer)) != -1) {
            clientOut.write(buffer, 0, len);
        }
        clientOut.flush();

        remoteSocket.close();
    }

    private void runTunnel(Socket client, Socket remote) {
        Thread t1 = new Thread(() -> {
            InputStream in = null;
            OutputStream out = null;
            try {
                in = client.getInputStream();
                out = remote.getOutputStream();
                byte[] buf = new byte[8192];
                int len;
                while ((len = in.read(buf)) != -1) {
                    out.write(buf, 0, len);
                    out.flush(); // Важно для Windows/curl
                }
            } catch (IOException e) {
                logger.debug("Tunnel thread 1 ended: {}", e.getMessage());
            } finally {
                try { if (in != null) in.close(); } catch (IOException ignored) {}
                try { if (out != null) out.close(); } catch (IOException ignored) {}
            }
        });

        Thread t2 = new Thread(() -> {
            InputStream in = null;
            OutputStream out = null;
            try {
                in = remote.getInputStream();
                out = client.getOutputStream();
                byte[] buf = new byte[8192];
                int len;
                while ((len = in.read(buf)) != -1) {
                    out.write(buf, 0, len);
                    out.flush();
                }
            } catch (IOException e) {
                logger.debug("Tunnel thread 2 ended: {}", e.getMessage());
            } finally {
                try { if (in != null) in.close(); } catch (IOException ignored) {}
                try { if (out != null) out.close(); } catch (IOException ignored) {}
            }
        });

        t1.setDaemon(true);
        t2.setDaemon(true);
        t1.start();
        t2.start();

        try {
            t1.join();
            t2.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        try { client.close(); } catch (IOException ignored) {}
        try { remote.close(); } catch (IOException ignored) {}
    }

    private String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                if (!sb.toString().isEmpty() && sb.charAt(sb.length() - 1) == '\r') {
                    sb.setLength(sb.length() - 1);
                }
                return sb.toString();
            }
            sb.append((char) c);
        }
        return !sb.isEmpty() ? sb.toString() : null;
    }

    private void sendError(OutputStream out, int code, String message) throws IOException {
        String body = "<html><body><h1>" + code + " " + message + "</h1></body></html>";
        String response = "HTTP/1.1 " + code + " " + message + "\r\n" +
                "Content-Type: text/html\r\n" +
                "Content-Length: " + body.length() + "\r\n" +
                "Connection: close\r\n" +
                "\r\n" +
                body;
        out.write(response.getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
    }
}