/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.compressor.compression;

import com.jcraft.jzlib.Deflater;
import com.jcraft.jzlib.Inflater;
import com.jcraft.jzlib.JZlib;
import de.rub.nds.sshattacker.core.constants.CompressionAlgorithm;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class DeflateCompression extends Compression {

    private static final int BUFFER_SIZE = 4096;
    private final Deflater deflater;
    private final Inflater inflater;

    public DeflateCompression() {
        super(CompressionAlgorithm.DEFLATE);
        deflater = new Deflater();
        inflater = new Inflater();
        init();
    }

    private void init() {
        deflater.init(JZlib.Z_DEFAULT_COMPRESSION);
        inflater.init();
    }

    public byte[] compress(byte[] data) {
        ByteArrayOutputStream compressedOutputStream = new ByteArrayOutputStream();
        deflater.setInput(data);
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            deflater.setOutput(buffer, 0, BUFFER_SIZE);
            int status = deflater.deflate(JZlib.Z_PARTIAL_FLUSH);
            if (status != JZlib.Z_OK) {
                LOGGER.error(
                        "Unable to compress the provided data, deflate status is not equal to Z_OK: {}",
                        status);
                return null;
            }
            compressedOutputStream.write(buffer, 0, BUFFER_SIZE - deflater.getAvailOut());
        } while (deflater.getAvailOut() == 0);

        try {
            compressedOutputStream.close();
            return compressedOutputStream.toByteArray();
        } catch (IOException e) {
            LOGGER.error("Unable to close compressed output stream after payload compression", e);
            return null;
        }
    }

    public byte[] decompress(byte[] data) {
        ByteArrayOutputStream uncompressedOutputStream = new ByteArrayOutputStream();
        inflater.setInput(data);
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            inflater.setOutput(buffer, 0, BUFFER_SIZE);
            int status = inflater.inflate(JZlib.Z_PARTIAL_FLUSH);
            if (status != JZlib.Z_OK) {
                LOGGER.error(
                        "Unable to decompress the provided data, inflate status is not equal to Z_OK: {}",
                        status);
                return null;
            }
            uncompressedOutputStream.write(buffer, 0, BUFFER_SIZE - inflater.getAvailOut());
        } while (inflater.getAvailOut() == 0);

        try {
            uncompressedOutputStream.close();
            return uncompressedOutputStream.toByteArray();
        } catch (IOException e) {
            LOGGER.error(
                    "Unable to close decompressed output stream after payload decompression", e);
            return null;
        }
    }
}
