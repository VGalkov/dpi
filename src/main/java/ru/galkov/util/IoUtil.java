package ru.galkov.util;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public final class IoUtil {

    private IoUtil() {
    }

    public static void closeQuietly(Socket s) {
        if (s == null || s.isClosed()) return;
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }

    public static void closeQuietly(DatagramSocket s) {
        if (s == null || s.isClosed()) return;
        try {
            s.close();
        } catch (Exception ignored) {
        }
    }

    public static void closeQuietly(ServerSocket s) {
        if (s == null || s.isClosed()) return;
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }
}