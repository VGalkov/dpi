package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.StringTokenizer;

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
            } catch (IOException ignored) {
            }
        }
    }

    private void handleConnect(
            InputStream clientIn,
            OutputStream clientOut,
            String target) throws IOException {

        String line;

        while ((line = readLine(clientIn)) != null) {
            if (line.isEmpty()) {
                break;
            }
        }

        if (line == null) {
            sendError(
                    clientOut,
                    400,
                    "Incomplete CONNECT request"
            );
            return;
        }

        int colonIndex = target.lastIndexOf(':');

        if (colonIndex <= 0 || colonIndex == target.length() - 1) {

            sendError(
                    clientOut,
                    400,
                    "Bad Request (invalid host and port)"
            );
            return;
        }

        String host = target.substring(0, colonIndex);

        String portText = target.substring(colonIndex + 1);

        int port;

        try {
            port = Integer.parseInt(portText);

        } catch (NumberFormatException e) {
            sendError(clientOut, 400, "Invalid port");
            return;
        }

        if (port < 1 || port > 65535) {
            sendError(clientOut, 400, "Invalid port");
            return;
        }

        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        if (host.isEmpty()) {
            sendError(
                    clientOut,
                    400,
                    "Empty host"
            );
            return;
        }

        logger.info(
                "{} -> CONNECT {}:{}",
                clientIp,
                host,
                port
        );

        /*
         * Проверяем домен или IP до подключения.
         * Порт в blacklist не передаётся, поэтому правило
         * блокирует этот host на любом порту.
         */
        if (blacklist != null &&
                blacklist.isBlocked(
                        host,
                        clientIp
                )) {

            logger.info(
                    "{} <- CONNECT заблокирован: {}:{}",
                    clientIp,
                    host,
                    port
            );

            sendError(
                    clientOut,
                    403,
                    "Forbidden"
            );

            return;
        }

        Socket remoteSocket =
                new Socket();

        try {
            remoteSocket.connect(
                    new java.net.InetSocketAddress(
                            host,
                            port
                    ),
                    10000
            );

            remoteSocket.setTcpNoDelay(true);
            clientSocket.setTcpNoDelay(true);

        } catch (IOException e) {
            try {
                remoteSocket.close();
            } catch (IOException ignored) {
            }

            sendError(
                    clientOut,
                    502,
                    "Bad Gateway"
            );

            logger.error(
                    "{} -> Не удалось подключиться к {}:{}",
                    clientIp,
                    host,
                    port,
                    e
            );

            return;
        }

        String response =
                "HTTP/1.1 200 Connection established\r\n" +
                        "Proxy-Agent: MyProxy\r\n" +
                        "\r\n";

        clientOut.write(
                response.getBytes(
                        StandardCharsets.ISO_8859_1
                )
        );

        clientOut.flush();

        logger.info("{} <- CONNECT туннель установлен: {}:{}", clientIp, host, port);

        runTunnel(
                clientSocket,
                remoteSocket
        );
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
                } catch (NumberFormatException ignored) {
                }
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

    private void runTunnel(
            final Socket client,
            final Socket remote) {

        Thread clientToRemote =
                new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                pipe(
                                        client,
                                        remote,
                                        "client -> remote"
                                );
                            }
                        },
                        "Proxy-Tunnel-ClientToRemote"
                );

        Thread remoteToClient =
                new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                pipe(
                                        remote,
                                        client,
                                        "remote -> client"
                                );
                            }
                        },
                        "Proxy-Tunnel-RemoteToClient"
                );

        clientToRemote.setDaemon(true);
        remoteToClient.setDaemon(true);

        clientToRemote.start();
        remoteToClient.start();

        try {
            clientToRemote.join();
            remoteToClient.join();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

            closeQuietly(client);
            closeQuietly(remote);

        } finally {
            closeQuietly(client);
            closeQuietly(remote);
        }
    }

    private void closeQuietly(
            Socket socket) {

        if (socket == null) {
            return;
        }

        try {
            socket.close();

        } catch (IOException e) {
            logger.trace(
                    "Ошибка закрытия tunnel socket: {}",
                    e.getMessage()
            );
        }
    }

    private void pipe(
            Socket source,
            Socket destination,
            String direction) {

        byte[] buffer =
                new byte[8192];

        logger.info(
                "Tunnel {}: поток запущен, source={}, destination={}",
                direction,
                source.getRemoteSocketAddress(),
                destination.getRemoteSocketAddress()
        );

        //long totalBytes = 0L;
        try {
            InputStream input = source.getInputStream();
            OutputStream output = destination.getOutputStream();

            int length;
            while ((length = input.read(buffer)) != -1) {
                output.write(buffer, 0, length);
                output.flush();

                //totalBytes += length;
                //logger.info("Tunnel {}: передано {} байт, всего {}", direction, length, totalBytes);
            }

            // logger.info("Tunnel {}: EOF, всего передано {} байт", direction, totalBytes);

        } catch (IOException e) {
          //  logger.info("Tunnel {}: остановлен после {} байт: {}", direction, totalBytes, e.getMessage());
        }
    }

    private String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;

        while ((c = in.read()) != -1) {
            if (c == '\n') {
                int length = sb.length();

                if (length > 0 && sb.charAt(length - 1) == '\r') {
                    sb.setLength(length - 1);
                }
                return sb.toString();
            }

            sb.append((char) c);
        }

        return sb.length() > 0 ? sb.toString() : null;
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