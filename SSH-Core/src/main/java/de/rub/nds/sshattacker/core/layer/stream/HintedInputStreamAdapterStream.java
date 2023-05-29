/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.stream;

import de.rub.nds.sshattacker.core.layer.hints.LayerProcessingHint;
import java.io.IOException;
import java.io.InputStream;

/**
 * HintedInputStream, that wraps around another Stream (used in the {@link
 * de.rub.nds.tlsattacker.core.layer.impl.TcpLayer} and the {@link
 * de.rub.nds.tlsattacker.core.layer.impl.UdpLayer}
 */
public class HintedInputStreamAdapterStream extends HintedInputStream {

    private InputStream stream;

    public HintedInputStreamAdapterStream(LayerProcessingHint hint, InputStream stream) {
        super(hint);
        this.stream = stream;
    }

    @Override
    protected InputStream getDataSource() {
        return stream;
    }

    @Override
    public int read() throws IOException {
        return stream.read();
    }

    @Override
    public int available() throws IOException {
        return stream.available();
    }

    @Override
    public void extendStream(byte[] bytes) {
        throw new UnsupportedOperationException(
                "HintedInputStreamAdapterStream is not extendable.");
    }
}
