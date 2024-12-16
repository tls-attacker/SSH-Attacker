/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.compressor.compression;

import com.jcraft.jzlib.Deflater;
import com.jcraft.jzlib.Inflater;
import com.jcraft.jzlib.JZlib;
import de.rub.nds.sshattacker.core.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CompressionException;
import de.rub.nds.sshattacker.core.exceptions.DecompressionException;
import java.io.ByteArrayOutputStream;

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

    public byte[] compress(byte[] data) throws CompressionException {
        ByteArrayOutputStream compressedOutputStream = new ByteArrayOutputStream();
        deflater.setInput(data);
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            deflater.setOutput(buffer, 0, BUFFER_SIZE);
            int status = deflater.deflate(JZlib.Z_PARTIAL_FLUSH);
            if (status != JZlib.Z_OK) {
                throw new CompressionException(
                        "Unable to compress the provided data, deflate status is not equal to Z_OK: "
                                + status);
            }
            compressedOutputStream.write(buffer, 0, BUFFER_SIZE - deflater.getAvailOut());
        } while (deflater.getAvailOut() == 0);

        return compressedOutputStream.toByteArray();
    }

    public byte[] decompress(byte[] data) throws DecompressionException {
        ByteArrayOutputStream uncompressedOutputStream = new ByteArrayOutputStream();
        inflater.setInput(data);
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            inflater.setOutput(buffer, 0, BUFFER_SIZE);
            int status = inflater.inflate(JZlib.Z_PARTIAL_FLUSH);
            if (status != JZlib.Z_OK) {
                throw new DecompressionException(
                        "Unable to decompress the provided data, inflate status is not equal to Z_OK: "
                                + status);
            }
            uncompressedOutputStream.write(buffer, 0, BUFFER_SIZE - inflater.getAvailOut());
        } while (inflater.getAvailOut() == 0);

        return uncompressedOutputStream.toByteArray();
    }
}
