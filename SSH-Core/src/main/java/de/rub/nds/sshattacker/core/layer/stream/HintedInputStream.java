/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.stream;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import java.io.IOException;
import java.io.InputStream;

/**
 * InputStream that contains a LayerProcessingHint. Also provides methods useful when parsing data
 * from byteArrays.
 */
public abstract class HintedInputStream extends InputStream {

    public HintedInputStream() {}

    public byte readByte() throws IOException {
        return (byte) read();
    }

    public int readInt(int size) throws IOException {
        if (size < 0 || size > 4) {
            throw new ParserException("Cannot read Integer of size " + size);
        }
        byte[] readChunk = readChunk(size);
        return ArrayConverter.bytesToInt(readChunk);
    }

    public byte[] readChunk(int size) throws IOException {
        if (size == 0) {
            return new byte[0];
        }
        byte[] chunk = new byte[size];
        int read = read(chunk);
        if (read != size) {
            throw new EndOfStreamException(
                    "Could not read "
                            + size
                            + " bytes from the stream. Only "
                            + read
                            + " bytes available");
        }
        return chunk;
    }

    protected abstract InputStream getDataSource();

    public abstract void extendStream(byte[] bytes);
}
