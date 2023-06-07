/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.preparator;

import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.compressor.PacketCompressor;
import de.rub.nds.sshattacker.core.packet.crypto.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobPacketPreparator extends AbstractPacketPreparator<BlobPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AbstractPacketEncryptor encryptor;
    private final PacketCompressor compressor;

    public BlobPacketPreparator(
            Chooser chooser,
            BlobPacket packet,
            AbstractPacketEncryptor encryptor,
            PacketCompressor compressor) {
        super(chooser, packet);
        this.encryptor = encryptor;
        this.compressor = compressor;
    }


    @Override
    public void prepare() {
        LOGGER.debug(
                "Compressing BlobPacket using {} compression algorithm",
                compressor.getCompressionAlgorithm());
        compressor.compress(getObject());
        LOGGER.debug("Encrypting BlobPacket");
        encryptor.encrypt(getObject());
    }
}
