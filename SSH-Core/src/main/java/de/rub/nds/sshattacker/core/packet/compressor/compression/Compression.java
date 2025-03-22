/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.compressor.compression;

import de.rub.nds.sshattacker.core.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CompressionException;
import de.rub.nds.sshattacker.core.exceptions.DecompressionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Compression {

    protected static final Logger LOGGER = LogManager.getLogger();
    protected final CompressionAlgorithm algorithm;

    protected Compression(CompressionAlgorithm algorithm) {
        super();
        this.algorithm = algorithm;
    }

    public abstract byte[] compress(byte[] data) throws CompressionException;

    public abstract byte[] decompress(byte[] data) throws DecompressionException;

    public CompressionAlgorithm getAlgorithm() {
        return algorithm;
    }
}
