/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SerializerStream extends ByteArrayOutputStream {
    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Adds a byte[] representation of an int to the final byte[]. If the Integer is greater than
     * the specified length only the lower length bytes are serialized.
     *
     * @param i The Integer that should be appended
     * @param length The number of bytes which should be reserved for this Integer
     */
    public final void appendInt(int i, int length) {
        byte[] bytes = ArrayConverter.intToBytes(i, length);
        int reconvertedInt = ArrayConverter.bytesToInt(bytes);
        if (reconvertedInt != i) {
            LOGGER.warn(
                    "Int \"{}\" is too long to write in field of size {}. Only using last {} bytes.",
                    i,
                    length,
                    length);
        }
        appendBytes(bytes);
    }

    /**
     * Adds a byte[] representation of a long to the final byte[]. If the Long is greater than the
     * specified length only the lower length bytes are serialized.
     *
     * @param l The Long that should be appended
     * @param length The number of bytes which should be reserved for this Long
     */
    public final void appendLong(long l, int length) {
        byte[] bytes = ArrayConverter.longToBytes(l, length);
        long reconvertedLong = ArrayConverter.bytesToLong(bytes);
        if (reconvertedLong != l) {
            LOGGER.warn(
                    "Long \"{}\" is too long to write in field of size {}. Only using last {} bytes.",
                    l,
                    length,
                    length);
        }
        appendBytes(bytes);
    }

    /**
     * Adds a byte[] representation of a BigInteger to the final byte[] minus the sign byte. If the
     * BigInteger is greater than the specified length only the lower length bytes are serialized.
     *
     * @param bigInteger The BigInteger that should be appended
     * @param length The number of bytes which should be reserved for this BigInteger
     */
    public final void appendBigInteger(BigInteger bigInteger, int length) {
        byte[] bytes;
        if (bigInteger.equals(BigInteger.ZERO)) {
            bytes = ArrayConverter.intToBytes(0, length);
        } else {
            bytes = ArrayConverter.bigIntegerToByteArray(bigInteger, length, true);
        }
        appendBytes(bytes);
    }

    /**
     * Adds a byte to the final byte[].
     *
     * @param b Byte which should be added
     */
    public final void appendByte(byte b) {
        write(b);
    }

    /**
     * Adds a byte[] to the final byte[].
     *
     * @param bytes bytes that should be added
     */
    public final void appendBytes(byte[] bytes) {
        try {
            write(bytes);
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug("Exception details: ", ex);
        }
    }

    /**
     * Adds a string (using UTF-8 encoding) to the final byte[]
     *
     * @param s String which should be added
     */
    public final void appendString(String s) {
        appendString(s, StandardCharsets.UTF_8);
    }

    /**
     * Adds a string (using the specified charset) to the final byte[]
     *
     * @param s String which should be added
     * @param charset Charset used to convert the string into bytes
     */
    public final void appendString(String s, Charset charset) {
        appendBytes(s.getBytes(charset));
    }
}
