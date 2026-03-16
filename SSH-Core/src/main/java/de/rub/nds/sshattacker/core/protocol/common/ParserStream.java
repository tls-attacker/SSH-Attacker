package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class ParserStream extends ByteArrayInputStream {

    public ParserStream(byte[] buf) {
        super(buf);
    }

    public ParserStream(byte[] buf, int offset) {
        super(buf, offset, buf.length - offset);
    }

    public ParserStream(byte[] buf, int offset, int length) {
        super(buf, offset, length);
    }

    public final int readInt() throws IOException {
        return DataConverter.bytesToInt(readNBytes(DataFormatConstants.UINT32_SIZE));
    }

    public final long readLong() throws IOException {
        return DataConverter.bytesToLong(readNBytes(DataFormatConstants.UINT64_SIZE));
    }

    public final BigInteger readBigInteger(int length) throws IOException {
        return new BigInteger(1, readNBytes(length));
    }

    public final byte readByte() throws IOException {
        int value = read();
        if (value == -1) {
            throw new IOException("End of stream reached");
        }
        return (byte) value;
    }

    public final byte[] readBytes(int length) throws IOException {
        return readNBytes(length);
    }

    public final String readString(int length) throws IOException {
        byte[] stringBytes = readNBytes(length);
        return new String(stringBytes, StandardCharsets.UTF_8);
    }

    public final String readString(int length, String charset) throws IOException {
        byte[] stringBytes = readNBytes(length);
        return new String(stringBytes, charset);
    }

    public final String readStringUntil(byte delimiter) {
        return readStringUntil(delimiter, StandardCharsets.UTF_8);
    }

    public final String readStringUntil(byte delimiter, Charset charset) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int value;
        while ((value = read()) != -1) {
            if ((byte) value == delimiter) {
                break;
            }
            buffer.write(value);
        }
        return buffer.toString(charset);
    }

    public final Pair<Integer, String> readLengthPrefixedString() throws IOException {
        int length = readInt();
        String value = readString(length);
        return new Pair<>(length, value);
    }

    public final Pair<Integer, BigInteger> readLengthPrefixedBigInteger() throws IOException {
        int length = readInt();
        BigInteger value = readBigInteger(length);
        return new Pair<>(length, value);
    }

    public final Pair<Integer, byte[]> readLengthPrefixedBytes() throws IOException {
        int length = readInt();
        byte[] value = readBytes(length);
        return new Pair<>(length, value);
    }
}
