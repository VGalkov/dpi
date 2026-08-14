package ru.galkov.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.StringTokenizer;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class ProxyHandler implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ProxyHandler.class);

    private static final int CONNECT_TIMEOUT_MILLIS = 10000;
    private static final int TLS_HELLO_TIMEOUT_MILLIS = 10000;
    private static final int MAX_TLS_RECORD_LENGTH = 18432;
    private static final int MAX_TLS_CLIENT_HELLO_LENGTH = 65536;

    private final Socket clientSocket;
    private final String clientIp;
    private final BlacklistLoader blacklist;

    public ProxyHandler(Socket clientSocket, String clientIp, BlacklistLoader blacklist) {
        this.clientSocket = clientSocket;
        this.clientIp = clientIp;
        this.blacklist = blacklist;
    }

    @Override
    public void run() {
        try {
            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();

            String firstLine = readLine(clientIn);
            if (firstLine == null || firstLine.isEmpty()) {
                logger.debug("{} -> Empty request", clientIp);
                return;
            }

            logger.trace("{} -> Request: {}", clientIp, firstLine);

            StringTokenizer tokens = new StringTokenizer(firstLine);
            if (!tokens.hasMoreTokens()) {
                sendError(clientOut, 400, "Bad Request");
                return;
            }

            String method = tokens.nextToken().toUpperCase(Locale.ROOT);
            if (!tokens.hasMoreTokens()) {
                sendError(clientOut, 400, "Bad Request (no target)");
                return;
            }

            String target = tokens.nextToken();

            if ("CONNECT".equals(method)) {
                handleConnect(clientIn, clientOut, target);
                return;
            }

            if ("GET".equals(method) || "POST".equals(method) || "HEAD".equals(method)
                    || "PUT".equals(method) || "DELETE".equals(method)) {
                handleHttp(clientIn, clientOut, firstLine, target, method);
                return;
            }

            sendError(clientOut, 501, "Not Implemented");

        } catch (IOException e) {
            if (!(e instanceof java.net.SocketException)) {
                logger.warn("Network error for client {}: {}", clientIp, e.getMessage());
            }
        } finally {
            closeQuietly(clientSocket);
        }
    }

    private void handleConnect(InputStream clientIn, OutputStream clientOut, String target) throws IOException {
        readAndDiscardHeaders(clientIn);

        HostAndPort hostAndPort = parseConnectTarget(target);
        if (hostAndPort == null) {
            sendError(clientOut, 400, "Bad Request (invalid host and port)");
            return;
        }

        String host = hostAndPort.host;
        int port = hostAndPort.port;

        logger.info("{} -> CONNECT {}:{}", clientIp, host, port);

        if (isBlockedHostOrIp(host)) {
            logger.info("{} <- CONNECT заблокирован по host/IP: {}:{}", clientIp, host, port);
            sendError(clientOut, 403, "Forbidden");
            return;
        }

        Socket remoteSocket = new Socket();

        try {
            remoteSocket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MILLIS);
            remoteSocket.setTcpNoDelay(true);
            clientSocket.setTcpNoDelay(true);

            String response = """
                    HTTP/1.1 200 Connection established\r
                    Proxy-Agent: MyProxy\r
                    \r
                    """;

            clientOut.write(response.getBytes(StandardCharsets.ISO_8859_1));
            clientOut.flush();

            byte[] clientHelloBytes = readInitialTlsHandshake(clientIn);
            if (clientHelloBytes == null) {
                logger.warn("{} -> CONNECT {}:{}: TLS ClientHello не получен, SNI не проверен",
                        clientIp, host, port);
                runTunnel(clientSocket, remoteSocket);
                return;
            }

            String sniHost = extractSniFromTlsHandshake(clientHelloBytes);

            if (sniHost != null) {
                logger.info("{} -> CONNECT {}:{}: SNI={}", clientIp, host, port, sniHost);

                if (blacklist != null && blacklist.isBlockedDomain(sniHost)) {
                    logger.info("{} <- CONNECT заблокирован по SNI: {}", clientIp, sniHost);
                    closeQuietly(remoteSocket);
                    return;
                }
            } else {
                logger.warn("{} -> CONNECT {}:{}: SNI отсутствует или ClientHello не разобран",
                        clientIp, host, port);
            }

            OutputStream remoteOut = remoteSocket.getOutputStream();
            remoteOut.write(clientHelloBytes);
            remoteOut.flush();

            logger.info("{} <- CONNECT туннель установлен: {}:{}", clientIp, host, port);
            runTunnel(clientSocket, remoteSocket);

        } catch (IOException e) {
            closeQuietly(remoteSocket);

            if (!clientSocket.isClosed()) {
                sendError(clientOut, 502, "Bad Gateway");
            }

            logger.warn("{} -> Не удалось создать CONNECT-туннель {}:{}: {}",
                    clientIp, host, port, e.getMessage());
        }
    }

    private void readAndDiscardHeaders(InputStream clientIn) throws IOException {
        String line;

        while ((line = readLine(clientIn)) != null) {
            if (line.isEmpty()) {
                return;
            }
        }

        throw new IOException("Incomplete CONNECT request");
    }

    private HostAndPort parseConnectTarget(String target) {
        if (target == null || target.isEmpty()) {
            return null;
        }

        String host;
        String portText;

        if (target.startsWith("[")) {
            int closingBracket = target.indexOf(']');

            if (closingBracket <= 1 || closingBracket + 1 >= target.length()
                    || target.charAt(closingBracket + 1) != ':') {
                return null;
            }

            host = target.substring(1, closingBracket);
            portText = target.substring(closingBracket + 2);
        } else {
            int colonIndex = target.lastIndexOf(':');

            if (colonIndex <= 0 || colonIndex == target.length() - 1) {
                return null;
            }

            host = target.substring(0, colonIndex);
            portText = target.substring(colonIndex + 1);

            if (host.indexOf(':') >= 0) {
                return null;
            }
        }

        int port;

        try {
            port = Integer.parseInt(portText);
        } catch (NumberFormatException e) {
            return null;
        }

        if (port < 1 || port > 65535) {
            return null;
        }

        return new HostAndPort(host, port);
    }

    private boolean isBlockedHostOrIp(String host) {
        if (blacklist == null) {
            return false;
        }

        return blacklist.isBlockedIp(host) || blacklist.isBlockedDomain(host);
    }

    private byte[] readInitialTlsHandshake(InputStream input) throws IOException {
        int originalTimeout = clientSocket.getSoTimeout();

        try {
            clientSocket.setSoTimeout(TLS_HELLO_TIMEOUT_MILLIS);

            byte[] firstHeader = readExactly(input, 5);
            if (firstHeader == null) {
                return null;
            }

            int contentType = unsignedByte(firstHeader[0]);
            int recordLength = unsignedShort(firstHeader[3], firstHeader[4]);

            if (recordLength < 1 || recordLength > MAX_TLS_RECORD_LENGTH) {
                logger.warn("{} -> TLS record имеет некорректную длину: {}", clientIp, recordLength);
                return firstHeader;
            }

            byte[] firstPayload = readExactly(input, recordLength);
            if (firstPayload == null) {
                return firstHeader;
            }

            ByteArrayOutputStream result = new ByteArrayOutputStream(5 + recordLength);
            result.write(firstHeader);
            result.write(firstPayload);

            if (contentType != 22) {
                return result.toByteArray();
            }

            int handshakeLength = getTlsHandshakeLength(firstPayload);
            if (handshakeLength < 0 || handshakeLength > MAX_TLS_CLIENT_HELLO_LENGTH) {
                return result.toByteArray();
            }

            int requiredHandshakeBytes = 4 + handshakeLength;
            int alreadyReadHandshakeBytes = firstPayload.length;

            while (alreadyReadHandshakeBytes < requiredHandshakeBytes) {
                byte[] nextHeader = readExactly(input, 5);
                if (nextHeader == null) {
                    break;
                }

                int nextContentType = unsignedByte(nextHeader[0]);
                int nextRecordLength = unsignedShort(nextHeader[3], nextHeader[4]);

                if (nextRecordLength < 1 || nextRecordLength > MAX_TLS_RECORD_LENGTH) {
                    result.write(nextHeader);
                    break;
                }

                byte[] nextPayload = readExactly(input, nextRecordLength);

                result.write(nextHeader);

                if (nextPayload == null) {
                    break;
                }

                result.write(nextPayload);

                if (nextContentType != 22) {
                    break;
                }

                alreadyReadHandshakeBytes += nextPayload.length;
            }

            return result.toByteArray();

        } catch (SocketTimeoutException e) {
            logger.warn("{} -> Таймаут ожидания TLS ClientHello", clientIp);
            return null;
        } finally {
            clientSocket.setSoTimeout(originalTimeout);
        }
    }

    private String extractSniFromTlsHandshake(byte[] tlsData) {
        if (tlsData == null || tlsData.length < 9) {
            return null;
        }

        try {
            int offset = 0;
            ByteArrayOutputStream handshakeData = new ByteArrayOutputStream();

            while (offset + 5 <= tlsData.length) {
                int contentType = unsignedByte(tlsData[offset]);
                int recordLength = unsignedShort(tlsData[offset + 3], tlsData[offset + 4]);

                offset += 5;

                if (recordLength < 0 || offset + recordLength > tlsData.length) {
                    return null;
                }

                if (contentType == 22) {
                    handshakeData.write(tlsData, offset, recordLength);
                }

                offset += recordLength;
            }

            byte[] hello = handshakeData.toByteArray();

            if (hello.length < 4 || unsignedByte(hello[0]) != 1) {
                return null;
            }

            int handshakeLength = unsignedMedium(hello[1], hello[2], hello[3]);

            if (handshakeLength < 0 || handshakeLength + 4 > hello.length) {
                return null;
            }

            int position = 4;
            int end = 4 + handshakeLength;

            if (position + 2 + 32 > end) {
                return null;
            }

            position += 2;
            position += 32;

            if (position + 1 > end) {
                return null;
            }

            int sessionIdLength = unsignedByte(hello[position]);
            position += 1;

            if (position + sessionIdLength > end) {
                return null;
            }

            position += sessionIdLength;

            if (position + 2 > end) {
                return null;
            }

            int cipherSuitesLength = unsignedShort(hello[position], hello[position + 1]);
            position += 2;

            if (position + cipherSuitesLength > end) {
                return null;
            }

            position += cipherSuitesLength;

            if (position + 1 > end) {
                return null;
            }

            int compressionMethodsLength = unsignedByte(hello[position]);
            position += 1;

            if (position + compressionMethodsLength > end) {
                return null;
            }

            position += compressionMethodsLength;

            if (position == end) {
                return null;
            }

            if (position + 2 > end) {
                return null;
            }

            int extensionsLength = unsignedShort(hello[position], hello[position + 1]);
            position += 2;

            int extensionsEnd = position + extensionsLength;

            if (extensionsEnd > end) {
                return null;
            }

            while (position + 4 <= extensionsEnd) {
                int extensionType = unsignedShort(hello[position], hello[position + 1]);
                int extensionLength = unsignedShort(hello[position + 2], hello[position + 3]);

                position += 4;

                if (position + extensionLength > extensionsEnd) {
                    return null;
                }

                if (extensionType == 0) {
                    return extractServerName(hello, position, extensionLength);
                }

                position += extensionLength;
            }

            return null;

        } catch (RuntimeException e) {
            logger.debug("{} -> Ошибка разбора TLS ClientHello: {}", clientIp, e.getMessage());
            return null;
        }
    }

    private String extractServerName(byte[] hello, int offset, int length) {
        if (length < 2 || offset + length > hello.length) {
            return null;
        }

        int listLength = unsignedShort(hello[offset], hello[offset + 1]);
        int position = offset + 2;
        int end = position + listLength;

        if (end > offset + length) {
            return null;
        }

        while (position + 3 <= end) {
            int nameType = unsignedByte(hello[position]);
            int nameLength = unsignedShort(hello[position + 1], hello[position + 2]);

            position += 3;

            if (position + nameLength > end) {
                return null;
            }

            if (nameType == 0 && nameLength > 0) {
                String serverName = new String(hello, position, nameLength, StandardCharsets.US_ASCII);
                return HostNormalizer.normalizeHost(serverName);
            }

            position += nameLength;
        }

        return null;
    }

    private int getTlsHandshakeLength(byte[] payload) {
        if (payload == null || payload.length < 4 || unsignedByte(payload[0]) != 1) {
            return -1;
        }

        return unsignedMedium(payload[1], payload[2], payload[3]);
    }

    private byte[] readExactly(InputStream input, int length) throws IOException {
        byte[] result = new byte[length];
        int totalRead = 0;

        while (totalRead < length) {
            int read = input.read(result, totalRead, length - totalRead);

            if (read == -1) {
                return null;
            }

            totalRead += read;
        }

        return result;
    }

    private int unsignedByte(byte value) {
        return value & 0xFF;
    }

    private int unsignedShort(byte first, byte second) {
        return ((first & 0xFF) << 8) | (second & 0xFF);
    }

    private int unsignedMedium(byte first, byte second, byte third) {
        return ((first & 0xFF) << 16) | ((second & 0xFF) << 8) | (third & 0xFF);
    }

    private void handleHttp(InputStream clientIn, OutputStream clientOut, String firstLine,
                            String target, String method) throws IOException {

        StringBuilder headersBuilder = new StringBuilder();
        headersBuilder.append(firstLine).append("\r\n");

        String line;
        String hostHeader = null;
        long contentLength = -1;

        while ((line = readLine(clientIn)) != null && !line.isEmpty()) {
            headersBuilder.append(line).append("\r\n");

            String lowerLine = line.toLowerCase(Locale.ROOT);

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
            if (contentLength > Integer.MAX_VALUE) {
                sendError(clientOut, 413, "Payload Too Large");
                return;
            }

            body = new byte[(int) contentLength];

            int totalRead = 0;

            while (totalRead < contentLength) {
                int read = clientIn.read(body, totalRead, (int) contentLength - totalRead);

                if (read == -1) {
                    break;
                }

                totalRead += read;
            }
        }

        HostAndPort hostAndPort = resolveHttpTarget(hostHeader, target);

        if (hostAndPort == null) {
            sendError(clientOut, 400, "Cannot determine target host");
            return;
        }

        String finalHost = hostAndPort.host;
        int finalPort = hostAndPort.port;

        if (isBlockedHostOrIp(finalHost)) {
            logger.info("{} <- HTTP заблокирован по host/IP: {}:{}", clientIp, finalHost, finalPort);
            sendError(clientOut, 403, "Forbidden");
            return;
        }

        try (Socket remoteSocket = new Socket()) {
            remoteSocket.connect(new InetSocketAddress(finalHost, finalPort), CONNECT_TIMEOUT_MILLIS);

            OutputStream remoteOut = remoteSocket.getOutputStream();
            InputStream remoteIn = remoteSocket.getInputStream();

            String path = extractHttpPath(target);

            String finalRequest = method + " " + path + " HTTP/1.1\r\n" + headersBuilder;

            remoteOut.write(finalRequest.getBytes(StandardCharsets.ISO_8859_1));

            if (body.length > 0) {
                remoteOut.write(body);
            }

            remoteOut.flush();

            byte[] buffer = new byte[8192];
            int length;

            while ((length = remoteIn.read(buffer)) != -1) {
                clientOut.write(buffer, 0, length);
            }

            clientOut.flush();
        }
    }

    private HostAndPort resolveHttpTarget(String hostHeader, String target) {
        try {
            if (hostHeader != null && !hostHeader.isEmpty()) {
                return parseHttpHostHeader(hostHeader);
            }

            if (target.startsWith("http://") || target.startsWith("https://")) {
                URL url = new URL(target);

                String host = url.getHost();

                if (host == null || host.isEmpty()) {
                    return null;
                }

                int port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();

                if (port < 1 || port > 65535) {
                    return null;
                }

                return new HostAndPort(host, port);
            }

            return null;

        } catch (Exception e) {
            return null;
        }
    }

    private HostAndPort parseHttpHostHeader(String hostHeader) {
        if (hostHeader.startsWith("[")) {
            int closingBracket = hostHeader.indexOf(']');

            if (closingBracket <= 1) {
                return null;
            }

            String host = hostHeader.substring(1, closingBracket);

            if (closingBracket == hostHeader.length() - 1) {
                return new HostAndPort(host, 80);
            }

            if (hostHeader.charAt(closingBracket + 1) != ':') {
                return null;
            }

            int port = Integer.parseInt(hostHeader.substring(closingBracket + 2));

            if (port < 1 || port > 65535) {
                return null;
            }

            return new HostAndPort(host, port);
        }

        int colonIndex = hostHeader.lastIndexOf(':');

        if (colonIndex < 0) {
            return new HostAndPort(hostHeader, 80);
        }

        String host = hostHeader.substring(0, colonIndex);
        int port = Integer.parseInt(hostHeader.substring(colonIndex + 1));

        if (host.isEmpty() || port < 1 || port > 65535) {
            return null;
        }

        return new HostAndPort(host, port);
    }

    private String extractHttpPath(String target) throws IOException {
        if (!target.startsWith("http://") && !target.startsWith("https://")) {
            return target;
        }

        URL url = new URL(target);

        String path = url.getPath();

        if (path == null || path.isEmpty()) {
            path = "/";
        }

        if (url.getQuery() != null) {
            path += "?" + url.getQuery();
        }

        return path;
    }

    private void runTunnel(final Socket client, final Socket remote) {
        Thread clientToRemote = new Thread(
                () -> pipe(client, remote, "client -> remote"), "Proxy-Tunnel-ClientToRemote"
        );

        Thread remoteToClient = new Thread(
                () -> pipe(remote, client, "remote -> client"), "Proxy-Tunnel-RemoteToClient"
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
        } finally {
            closeQuietly(client);
            closeQuietly(remote);
        }
    }

    private void pipe(Socket source, Socket destination, String direction) {
        byte[] buffer = new byte[8192];

        logger.debug("Tunnel {}: source={}, destination={}",
                direction, source.getRemoteSocketAddress(), destination.getRemoteSocketAddress());

        try {
            InputStream input = source.getInputStream();
            OutputStream output = destination.getOutputStream();

            int length;

            while ((length = input.read(buffer)) != -1) {
                output.write(buffer, 0, length);
                output.flush();
            }

        } catch (IOException e) {
            logger.debug("Tunnel {} завершён: {}", direction, e.getMessage());
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

        return !sb.isEmpty() ? sb.toString() : null;
    }

    private void sendError(OutputStream out, int code, String message) throws IOException {
        String body = "<html><body><h1>" + code + " " + message + "</h1></body></html>";

        String response = "HTTP/1.1 " + code + " " + message + "\r\n"
                + "Content-Type: text/html\r\n"
                + "Content-Length: " + body.length() + "\r\n"
                + "Connection: close\r\n"
                + "\r\n"
                + body;

        out.write(response.getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
    }

    private void closeQuietly(Socket socket) {
        if (socket == null) {
            return;
        }

        try {
            socket.close();
        } catch (IOException e) {
            logger.trace("Ошибка закрытия socket: {}", e.getMessage());
        }
    }

    private static final class HostAndPort {
        private final String host;
        private final int port;

        private HostAndPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }
}