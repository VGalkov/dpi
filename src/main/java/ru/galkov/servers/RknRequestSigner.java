package ru.galkov.servers;

public interface RknRequestSigner {
    byte[] sign(byte[] data) throws Exception;
}