/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.packet.preparator;

import de.rub.nds.sshattacker.core.crypto.packet.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.protocol.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketPreparator extends AbstractPacketPreparator<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BinaryPacket binaryPacket;
    private final AbstractPacketEncryptor encryptor;

    public BinaryPacketPreparator(
            Chooser chooser, BinaryPacket binaryPacket, AbstractPacketEncryptor encryptor) {
        super(chooser, binaryPacket);
        this.binaryPacket = binaryPacket;
        this.encryptor = encryptor;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing binary packet");
        binaryPacket.prepareComputations();
        encrypt();
    }

    public void encrypt() {
        LOGGER.debug("Encrypting binary packet");
        encryptor.encrypt(binaryPacket);
    }
}
