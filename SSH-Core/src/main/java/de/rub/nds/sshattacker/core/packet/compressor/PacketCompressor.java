/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.compressor;

import de.rub.nds.sshattacker.core.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.compressor.compression.Compression;
import de.rub.nds.sshattacker.core.packet.compressor.compression.DeflateCompression;
import de.rub.nds.sshattacker.core.packet.compressor.compression.NoneCompression;

public class PacketCompressor extends Compressor<AbstractPacket> {

    private Compression compression;

    public PacketCompressor() {
        super();
        setCompressionAlgorithm(CompressionAlgorithm.NONE);
    }

    @Override
    public void compress(AbstractPacket packet) {
        packet.setCompressedPayload(compression.compress(packet.getPayload().getValue()));
    }

    public void setCompressionAlgorithm(CompressionAlgorithm algorithm) {
        LOGGER.debug(
                "Setting active compression algorithm for packet compression to {}", algorithm);
        if (algorithm == CompressionAlgorithm.DEFLATE) {
            compression = new DeflateCompression();
        } else {
            compression = new NoneCompression();
        }
    }

    public CompressionAlgorithm getCompressionAlgorithm() {
        return compression.getAlgorithm();
    }
}
