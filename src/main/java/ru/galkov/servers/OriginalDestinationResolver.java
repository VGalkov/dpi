package ru.galkov.servers;

import java.net.InetSocketAddress;
import java.net.Socket;

public final class OriginalDestinationResolver {
    private OriginalDestinationResolver() {
    }

    public static InetSocketAddress getOriginalDestination(Socket socket) {
        return null;
    }
}