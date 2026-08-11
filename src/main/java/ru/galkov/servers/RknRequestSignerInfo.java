package ru.galkov.servers;

public class RknRequestSignerInfo implements RknRequestSigner{
    @Override
    public byte[] sign(byte[] data) throws Exception {
        return new byte[0];
    }
}
