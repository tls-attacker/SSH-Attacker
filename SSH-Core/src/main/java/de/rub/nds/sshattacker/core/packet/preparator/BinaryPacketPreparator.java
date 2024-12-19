/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.preparator;

import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.compressor.PacketCompressor;
import de.rub.nds.sshattacker.core.packet.crypto.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketPreparator extends AbstractPacketPreparator<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AbstractPacketEncryptor encryptor;
    private final PacketCompressor compressor;

    public BinaryPacketPreparator(
            Chooser chooser,
            BinaryPacket binaryPacket,
            AbstractPacketEncryptor encryptor,
            PacketCompressor compressor) {
        super(chooser, binaryPacket);
        this.encryptor = encryptor;
        this.compressor = compressor;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing binary packet computations");
        object.prepareComputations();
        LOGGER.debug("Compressing binary packet");
        compressor.compress(object);
        LOGGER.debug("Encrypting binary packet");
        encryptor.encrypt(object);
    }
}
