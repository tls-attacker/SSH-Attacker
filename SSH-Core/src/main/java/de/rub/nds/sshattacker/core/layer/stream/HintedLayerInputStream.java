/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.stream;

import de.rub.nds.sshattacker.core.layer.ProtocolLayer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * The HintedLayerInputStream is assigned to a layer. When reading data from it, the stream tries to
 * receive more data using the layer it is assigned to.
 */
public class HintedLayerInputStream extends HintedInputStream {

    private final ProtocolLayer<?> layer;

    private ByteArrayInputStream stream = new ByteArrayInputStream(new byte[0]);

    public HintedLayerInputStream(ProtocolLayer<?> layer) {
        super();
        this.layer = layer;
    }

    /**
     * Return data from the underlaying stream. If none is present, write more data into the stream
     * using the layer.
     */
    @Override
    public int read() throws IOException {
        if (stream.available() > 0) {
            return stream.read();
        } else {
            layer.receiveMoreData();
            // either the stream is now filled, or we ran into a timeout
            // or the next stream is available
            return stream.read();
        }
    }

    @Override
    public int available() throws IOException {
        return stream.available();
    }

    @Override
    protected InputStream getDataSource() {
        return stream;
    }

    /** Extends the current data in the stream with the given data. */
    @Override
    public void extendStream(byte[] bytes) {
        try {
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();
            stream.transferTo(outStream);
            outStream.write(bytes);
            stream = new ByteArrayInputStream(outStream.toByteArray());
        } catch (IOException ex) {
            throw new RuntimeException("IO Exception from ByteArrayStream");
        }
    }
}
