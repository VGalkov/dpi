package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.HostNormalizer;
import ru.galkov.util.LogFields;

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

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506774@yandex.ru) Galkov V.A.
 */
public class ProxyHandler implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ProxyHandler.class);

    private static final int MAX_TLS_RECORD_LENGTH = 18432;
    private static final int MAX_TLS_CLIENT_HELLO_LENGTH = 65536;

    private final Socket clientSocket;
    private final String clientIp;
    private final BlacklistLoader blacklist;

    private final int connectTimeoutMillis;
    private final int clientReadTimeoutMillis;
    private final int remoteReadTimeoutMillis;
    private final int maxHeaderBytes;
    private final long maxBodyBytes;

    public ProxyHandler(Socket clientSocket, String clientIp, BlacklistLoader blacklist) {
        this.clientSocket = clientSocket;
        this.clientIp = clientIp;
        this.blacklist = blacklist;
        this.connectTimeoutMillis = getConfig().getInt("proxy.connect-timeout-millis");
        this.clientReadTimeoutMillis = getConfig().getInt("proxy.client-read-timeout-millis");
        this.remoteReadTimeoutMillis = getConfig().getInt("proxy.remote-read-timeout-millis");
        this.maxHeaderBytes = getConfig().getInt("proxy.max-header-bytes");
        this.maxBodyBytes = getConfig().getLong("proxy.max-body-bytes");

        validateLimits();
    }

    @Override
    public void run() {
        try {
            clientSocket.setSoTimeout(clientReadTimeoutMillis);

            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();

            String firstLine = readLine(clientIn, maxHeaderBytes);

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

        } catch (RequestTooLargeException e) {
            logger.info("{} <- HTTP request header is too large: {}", clientIp, e.getMessage());
            sendErrorQuietly(431, "Request Header Fields Too Large");

        } catch (SocketTimeoutException e) {
            logger.info("{} <- HTTP connection timeout: {}", clientIp, e.getMessage());
            sendErrorQuietly(408, "Request Timeout");

        } catch (IOException e) {
            if (!(e instanceof java.net.SocketException)) {
                logger.warn("Network error for client {}: {}", clientIp, e.getMessage());
            }
        } finally {
            closeQuietly(clientSocket);
        }
    }

    private void validateLimits() {
        if (connectTimeoutMillis <= 0) {
            throw new IllegalArgumentException("proxy.connect-timeout-millis должен быть больше 0");
        }

        if (clientReadTimeoutMillis <= 0) {
            throw new IllegalArgumentException("proxy.client-read-timeout-millis должен быть больше 0");
        }

        if (remoteReadTimeoutMillis <= 0) {
            throw new IllegalArgumentException("proxy.remote-read-timeout-millis должен быть больше 0");
        }

        if (maxHeaderBytes < 1024) {
            throw new IllegalArgumentException("proxy.max-header-bytes должен быть не меньше 1024");
        }

        if (maxBodyBytes < 0) {
            throw new IllegalArgumentException("proxy.max-body-bytes не может быть отрицательным");
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

        logger.info("{} {} {} {}",
                LogFields.kv("event", "PROXY_CONNECT"),
                LogFields.kv("client", clientIp),
                LogFields.kv("host", host),
                LogFields.kv("port", port));

        if (isBlockedHostOrIp(host)) {
            logger.info("{} {} {} {} {}",
                    LogFields.kv("event", "PROXY_CONNECT_BLOCKED"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("host", host),
                    LogFields.kv("port", port),
                    LogFields.kv("reason", "HOST_IP"));
            sendError(clientOut, 403, "Forbidden");
            return;
        }

        Socket remoteSocket = new Socket();

        try {
            remoteSocket.connect(new InetSocketAddress(host, port), connectTimeoutMillis);
            remoteSocket.setSoTimeout(remoteReadTimeoutMillis);
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
                logger.warn("{} -> CONNECT {}:{}: TLS ClientHello not received, SNI not checked",
                        clientIp, host, port);

                runTunnel(clientSocket, remoteSocket);
                return;
            }

            String sniHost = extractSniFromTlsHandshake(clientHelloBytes);

            if (sniHost != null) {
                logger.info("{} -> CONNECT {}:{}: SNI={}", clientIp, host, port, sniHost);

                if (blacklist != null && blacklist.isBlockedDomain(sniHost)) {
                    logger.info("{} {} {} {}",
                            LogFields.kv("event", "PROXY_CONNECT_BLOCKED"),
                            LogFields.kv("client", clientIp),
                            LogFields.kv("sni", sniHost),
                            LogFields.kv("reason", "SNI"));
                    closeQuietly(remoteSocket);
                    return;
                }
            } else {
                logger.warn("{} -> CONNECT {}:{}: SNI missing or ClientHello cannot be parsed",
                        clientIp, host, port);
            }

            OutputStream remoteOut = remoteSocket.getOutputStream();

            remoteOut.write(clientHelloBytes);
            remoteOut.flush();

            logger.info("{} {} {} {}",
                    LogFields.kv("event", "PROXY_CONNECT_ESTABLISHED"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("host", host),
                    LogFields.kv("port", port));

            runTunnel(clientSocket, remoteSocket);

        } catch (SocketTimeoutException e) {
            closeQuietly(remoteSocket);

            if (!clientSocket.isClosed()) {
                sendError(clientOut, 504, "Gateway Timeout");
            }

            logger.info("{} {} {} {}",
                    LogFields.kv("event", "PROXY_CONNECT_TIMEOUT"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("host", host),
                    LogFields.kv("port", port));

        } catch (IOException e) {
            closeQuietly(remoteSocket);

            if (!clientSocket.isClosed()) {
                sendError(clientOut, 502, "Bad Gateway");
            }

            logger.warn("{} -> Failed to create CONNECT tunnel {}:{}: {}",
                    clientIp, host, port, e.getMessage());
        }
    }

    private void readAndDiscardHeaders(InputStream clientIn) throws IOException {
        int totalHeaderBytes = 0;
        String line;

        while ((line = readLine(clientIn, maxHeaderBytes)) != null) {
            totalHeaderBytes += line.length() + 2;

            if (totalHeaderBytes > maxHeaderBytes) {
                throw new RequestTooLargeException("CONNECT headers exceed " + maxHeaderBytes + " bytes");
            }

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
            clientSocket.setSoTimeout(Math.min(clientReadTimeoutMillis, 10000));

            byte[] firstHeader = readExactly(input, 5);

            if (firstHeader == null) {
                return null;
            }

            int contentType = unsignedByte(firstHeader[0]);
            int recordLength = unsignedShort(firstHeader[3], firstHeader[4]);

            if (recordLength < 1 || recordLength > MAX_TLS_RECORD_LENGTH) {
                logger.warn("{} -> TLS record has invalid length: {}", clientIp, recordLength);
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

                if (result.size() > MAX_TLS_CLIENT_HELLO_LENGTH + 5 * 8) {
                    logger.warn("{} -> TLS ClientHello exceeds configured maximum", clientIp);
                    break;
                }
            }

            return result.toByteArray();

        } catch (SocketTimeoutException e) {
            logger.warn("{} -> Timeout waiting for TLS ClientHello", clientIp);
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

            if (position + 34 > end) {
                return null;
            }

            position += 2;
            position += 32;

            if (position + 1 > end) {
                return null;
            }

            int sessionIdLength = unsignedByte(hello[position]);
            position++;

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
            position++;

            if (position + compressionMethodsLength > end) {
                return null;
            }

            position += compressionMethodsLength;

            if (position == end || position + 2 > end) {
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
            logger.debug("{} -> TLS ClientHello parsing error: {}", clientIp, e.getMessage());
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

        HttpHeaders headers = readHttpHeaders(clientIn, firstLine);

        HostAndPort hostAndPort = resolveHttpTarget(headers.hostHeader, target);

        if (hostAndPort == null) {
            sendError(clientOut, 400, "Cannot determine target host");
            return;
        }

        String finalHost = hostAndPort.host;
        int finalPort = hostAndPort.port;

        if (isBlockedHostOrIp(finalHost)) {
            logger.info("{} {} {} {} {}",
                    LogFields.kv("event", "PROXY_HTTP_BLOCKED"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("host", finalHost),
                    LogFields.kv("port", finalPort),
                    LogFields.kv("reason", "HOST_IP"));
            sendError(clientOut, 403, "Forbidden");
            return;
        }

        if (headers.expectContinuePresent) {
            if (headers.chunked) {
                if (maxBodyBytes <= 0) {
                    sendError(clientOut, 413, "Payload Too Large");
                    return;
                }
            } else if (headers.contentLength > maxBodyBytes) {
                logger.info("{} {} {} {}",
                        LogFields.kv("event", "PROXY_HTTP_BODY_TOO_LARGE"),
                        LogFields.kv("client", clientIp),
                        LogFields.kv("size", headers.contentLength),
                        LogFields.kv("limit", maxBodyBytes));

                sendError(clientOut, 413, "Payload Too Large");
                return;
            }

            String continueResponse = "HTTP/1.1 100 Continue\r\n\r\n";
            clientOut.write(continueResponse.getBytes(StandardCharsets.ISO_8859_1));
            clientOut.flush();
        }

        try (Socket remoteSocket = new Socket()) {
            remoteSocket.connect(new InetSocketAddress(finalHost, finalPort), connectTimeoutMillis);
            remoteSocket.setSoTimeout(remoteReadTimeoutMillis);

            OutputStream remoteOut = remoteSocket.getOutputStream();
            InputStream remoteIn = remoteSocket.getInputStream();

            String path = extractHttpPath(target);

            String finalRequest = method + " " + path + " HTTP/1.1\r\n"
                    + headers.rawHeaders;

            remoteOut.write(finalRequest.getBytes(StandardCharsets.ISO_8859_1));

            if (headers.chunked) {
                relayChunkedRequestBody(clientIn, remoteOut);
            } else if (headers.contentLength > 0) {
                if (headers.contentLength > maxBodyBytes) {
                    logger.info("{} {} {} {}",
                            LogFields.kv("event", "PROXY_HTTP_BODY_TOO_LARGE"),
                            LogFields.kv("client", clientIp),
                            LogFields.kv("size", headers.contentLength),
                            LogFields.kv("limit", maxBodyBytes));

                    sendError(clientOut, 413, "Payload Too Large");
                    return;
                }

                relayFixedRequestBody(clientIn, remoteOut, headers.contentLength);
            }

            remoteOut.flush();

            relayHttpResponse(remoteIn, clientOut);

        } catch (SocketTimeoutException e) {
            logger.info("{} {} {} {}",
                    LogFields.kv("event", "PROXY_HTTP_UPSTREAM_TIMEOUT"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("host", finalHost),
                    LogFields.kv("port", finalPort));
            sendError(clientOut, 504, "Gateway Timeout");
        }
    }

    private HttpHeaders readHttpHeaders(InputStream clientIn, String firstLine) throws IOException {
        StringBuilder headersBuilder = new StringBuilder();
        headersBuilder.append(firstLine).append("\r\n");

        int totalHeaderBytes = firstLine.length() + 2;
        String hostHeader = null;
        Long contentLength = null;
        boolean chunked = false;
        boolean expectContinuePresent = false;

        String line;

        while ((line = readLine(clientIn, maxHeaderBytes)) != null && !line.isEmpty()) {
            totalHeaderBytes += line.length() + 2;

            if (totalHeaderBytes > maxHeaderBytes)
                throw new RequestTooLargeException("HTTP headers exceed " + maxHeaderBytes + " bytes");

            headersBuilder.append(line).append("\r\n");

            String lowerLine = line.toLowerCase(Locale.ROOT);

            if (lowerLine.startsWith("host:")) {
                hostHeader = line.substring(5).trim();
            } else if (lowerLine.startsWith("content-length:")) {
                Long parsedLength = parseContentLength(line.substring(15).trim());

                if (parsedLength == null)
                    throw new IOException("Invalid Content-Length");

                if (contentLength != null && contentLength.longValue() != parsedLength.longValue())
                    throw new IOException("Conflicting Content-Length headers");

                contentLength = parsedLength;

            } else if (lowerLine.startsWith("transfer-encoding:")) {
                String value = line.substring(18).trim().toLowerCase(Locale.ROOT);

                if (value.contains("chunked"))
                    chunked = true;

            } else if (lowerLine.startsWith("expect:")
                    && lowerLine.substring(7).trim().equals("100-continue")) {
                expectContinuePresent = true;
            }
        }

        if (line == null)
            throw new IOException("Incomplete HTTP request headers");

        headersBuilder.append("\r\n");

        return new HttpHeaders(
                headersBuilder.toString(),
                hostHeader,
                contentLength == null ? 0L : contentLength,
                chunked,
                expectContinuePresent
        );
    }

    private Long parseContentLength(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }

        try {
            long contentLength = Long.parseLong(value);

            if (contentLength < 0) {
                return null;
            }

            return contentLength;

        } catch (NumberFormatException e) {
            return null;
        }
    }

    private byte[] readRequestBody(InputStream clientIn, OutputStream clientOut, long contentLength)
            throws IOException {

        if (contentLength == 0) {
            return new byte[0];
        }

        if (contentLength > maxBodyBytes) {
            logger.info("{} {} {} {}",
                    LogFields.kv("event", "PROXY_HTTP_BODY_TOO_LARGE"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("size", contentLength),
                    LogFields.kv("limit", maxBodyBytes));

            sendError(clientOut, 413, "Payload Too Large");
            return null;
        }

        if (contentLength > Integer.MAX_VALUE) {
            sendError(clientOut, 413, "Payload Too Large");
            return null;
        }

        byte[] body = new byte[(int) contentLength];
        int totalRead = 0;

        while (totalRead < body.length) {
            int read = clientIn.read(body, totalRead, body.length - totalRead);

            if (read == -1) {
                throw new IOException("Unexpected end of request body");
            }

            totalRead += read;
        }

        return body;
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
                () -> pipe(client, remote, "client -> remote"),
                "Proxy-Tunnel-ClientToRemote"
        );

        Thread remoteToClient = new Thread(
                () -> pipe(remote, client, "remote -> client"),
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
        } finally {
            closeQuietly(client);
            closeQuietly(remote);
        }
    }

    private void pipe(Socket source, Socket destination, String direction) {
        byte[] buffer = new byte[8192];

        logger.debug("{} {} {} {}",
                LogFields.kv("event", "PROXY_TUNNEL"),
                LogFields.kv("direction", direction),
                LogFields.kv("source", source.getRemoteSocketAddress()),
                LogFields.kv("destination", destination.getRemoteSocketAddress()));

        try {
            InputStream input = source.getInputStream();
            OutputStream output = destination.getOutputStream();

            int length;

            while ((length = input.read(buffer)) != -1) {
                output.write(buffer, 0, length);
                output.flush();
            }

        } catch (SocketTimeoutException e) {
            logger.debug("Tunnel {} timeout", direction);
        } catch (IOException e) {
            logger.debug("Tunnel {} ended: {}", direction, e.getMessage());
        }
    }

    private String readLine(InputStream input, int maxLineBytes) throws IOException {
        StringBuilder result = new StringBuilder();

        while (true) {
            int currentByte = input.read();

            if (currentByte == -1) {
                return result.isEmpty() ? null : result.toString();
            }

            if (currentByte == '\n') {
                int length = result.length();

                if (length > 0 && result.charAt(length - 1) == '\r') {
                    result.setLength(length - 1);
                }

                return result.toString();
            }

            if (result.length() >= maxLineBytes) {
                throw new RequestTooLargeException("HTTP line exceeds " + maxLineBytes + " bytes");
            }

            result.append((char) currentByte);
        }
    }

    private void sendErrorQuietly(int code, String message) {
        try {
            if (!clientSocket.isClosed()) {
                sendError(clientSocket.getOutputStream(), code, message);
            }
        } catch (IOException ignored) {
        }
    }

    private void sendError(OutputStream out, int code, String message) throws IOException {
        String body = "<html><body><h1>" + code + " " + message + "</h1></body></html>";

        String response = "HTTP/1.1 " + code + " " + message + "\r\n"
                + "Content-Type: text/html; charset=UTF-8\r\n"
                + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                + "Connection: close\r\n"
                + "\r\n"
                + body;

        out.write(response.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private void closeQuietly(Socket socket) {
        if (socket == null) {
            return;
        }

        try {
            socket.close();
        } catch (IOException e) {
            logger.trace("Socket close error: {}", e.getMessage());
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

    private static final class HttpHeaders {
        private final String rawHeaders;
        private final String hostHeader;
        private final long contentLength;
        private final boolean chunked;
        private final boolean expectContinuePresent;

        private HttpHeaders(String rawHeaders, String hostHeader, long contentLength,
                            boolean chunked, boolean expectContinuePresent) {
            this.rawHeaders = rawHeaders;
            this.hostHeader = hostHeader;
            this.contentLength = contentLength;
            this.chunked = chunked;
            this.expectContinuePresent = expectContinuePresent;
        }
    }

    private static final class RequestTooLargeException extends IOException {
        private RequestTooLargeException(String message) {
            super(message);
        }
    }

    private void relayChunkedRequestBody(InputStream clientIn, OutputStream remoteOut) throws IOException {
        byte[] buffer = new byte[8192];
        long totalBytes = 0;

        while (true) {
            String chunkSizeLine = readLine(clientIn, 64);

            if (chunkSizeLine == null)
                throw new IOException("Unexpected end of chunked request body");

            int semicolon = chunkSizeLine.indexOf(';');
            String sizePart = semicolon >= 0 ? chunkSizeLine.substring(0, semicolon).trim() : chunkSizeLine.trim();

            int chunkSize;

            try {
                chunkSize = Integer.parseInt(sizePart, 16);
            } catch (NumberFormatException e) {
                throw new IOException("Invalid chunk size: " + sizePart);
            }

            if (chunkSize < 0)
                throw new IOException("Negative chunk size: " + chunkSize);

            if (chunkSize == 0) {
                readAndDiscardTrailers(clientIn);
                break;
            }

            if (totalBytes + chunkSize > maxBodyBytes) {
                logger.info("{} {} {} {}",
                        LogFields.kv("event", "PROXY_HTTP_BODY_TOO_LARGE"),
                        LogFields.kv("client", clientIp),
                        LogFields.kv("size", totalBytes + chunkSize),
                        LogFields.kv("limit", maxBodyBytes));

                throw new RequestTooLargeException("Chunked body exceeds " + maxBodyBytes + " bytes");
            }

            int remaining = chunkSize;

            while (remaining > 0) {
                int toRead = Math.min(remaining, buffer.length);
                int read = clientIn.read(buffer, 0, toRead);

                if (read == -1)
                    throw new IOException("Unexpected end of chunked request body");

                remoteOut.write(buffer, 0, read);
                remaining -= read;
            }

            totalBytes += chunkSize;

            readLine(clientIn, 2);
        }
    }

    private void readAndDiscardTrailers(InputStream clientIn) throws IOException {
        String line;

        while ((line = readLine(clientIn, maxHeaderBytes)) != null && !line.isEmpty()) {
        }
    }

    private void relayFixedRequestBody(InputStream clientIn, OutputStream remoteOut, long contentLength)
            throws IOException {

        byte[] buffer = new byte[8192];
        long remaining = contentLength;

        while (remaining > 0) {
            int toRead = (int) Math.min(remaining, buffer.length);
            int read = clientIn.read(buffer, 0, toRead);

            if (read == -1)
                throw new IOException("Unexpected end of request body");

            remoteOut.write(buffer, 0, read);
            remaining -= read;
        }
    }

    private void relayHttpResponse(InputStream remoteIn, OutputStream clientOut) throws IOException {
        String statusLine = readLine(remoteIn, maxHeaderBytes);

        if (statusLine == null) {
            logger.warn("Empty response from upstream");
            return;
        }

        writeLine(clientOut, statusLine);

        long contentLength = -1;
        boolean chunked = false;
        boolean connectionClose = false;
        String line;

        while ((line = readLine(remoteIn, maxHeaderBytes)) != null && !line.isEmpty()) {
            writeLine(clientOut, line);

            String lower = line.toLowerCase(Locale.ROOT);

            if (lower.startsWith("content-length:")) {
                String value = line.substring(15).trim();
                Long parsed = parseContentLength(value);

                if (parsed != null)
                    contentLength = parsed;

            } else if (lower.startsWith("transfer-encoding:")) {
                String value = line.substring(18).trim().toLowerCase(Locale.ROOT);

                if (value.contains("chunked"))
                    chunked = true;

            } else if (lower.startsWith("connection:")) {
                String value = line.substring(11).trim().toLowerCase(Locale.ROOT);

                if (value.contains("close"))
                    connectionClose = true;
            }
        }

        if (line == null)
            return;

        writeLine(clientOut, "");

        if (chunked) {
            relayChunkedResponseBody(remoteIn, clientOut);
        } else if (contentLength >= 0) {
            relayFixedResponseBody(remoteIn, clientOut, contentLength);
        } else {
            relayUntilEof(remoteIn, clientOut);
        }

        clientOut.flush();
    }

    private void relayChunkedResponseBody(InputStream remoteIn, OutputStream clientOut) throws IOException {
        byte[] buffer = new byte[8192];

        while (true) {
            String chunkSizeLine = readLine(remoteIn, 64);

            if (chunkSizeLine == null)
                break;

            writeLine(clientOut, chunkSizeLine);

            int semicolon = chunkSizeLine.indexOf(';');
            String sizePart = semicolon >= 0 ? chunkSizeLine.substring(0, semicolon).trim() : chunkSizeLine.trim();

            int chunkSize;

            try {
                chunkSize = Integer.parseInt(sizePart, 16);
            } catch (NumberFormatException e) {
                break;
            }

            if (chunkSize < 0)
                break;

            if (chunkSize == 0) {
                String trailerLine;

                while ((trailerLine = readLine(remoteIn, maxHeaderBytes)) != null && !trailerLine.isEmpty())
                    writeLine(clientOut, trailerLine);

                break;
            }

            int remaining = chunkSize;

            while (remaining > 0) {
                int toRead = Math.min(remaining, buffer.length);
                int read = remoteIn.read(buffer, 0, toRead);

                if (read == -1)
                    throw new IOException("Unexpected end of chunked response body");

                clientOut.write(buffer, 0, read);
                remaining -= read;
            }
        }
    }

    private void relayFixedResponseBody(InputStream remoteIn, OutputStream clientOut, long contentLength)
            throws IOException {

        byte[] buffer = new byte[8192];
        long remaining = contentLength;

        while (remaining > 0) {
            int toRead = (int) Math.min(remaining, buffer.length);
            int read = remoteIn.read(buffer, 0, toRead);

            if (read == -1)
                throw new IOException("Unexpected end of response body");

            clientOut.write(buffer, 0, read);
            remaining -= read;
        }
    }

    private void relayUntilEof(InputStream remoteIn, OutputStream clientOut) throws IOException {
        byte[] buffer = new byte[8192];
        int length;

        while ((length = remoteIn.read(buffer)) != -1)
            clientOut.write(buffer, 0, length);
    }

    private void writeLine(OutputStream out, String line) throws IOException {
        out.write(line.getBytes(StandardCharsets.ISO_8859_1));
        out.write('\r');
        out.write('\n');
    }
}