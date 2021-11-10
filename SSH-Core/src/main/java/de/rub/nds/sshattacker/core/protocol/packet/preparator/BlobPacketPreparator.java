/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.packet.preparator;

import de.rub.nds.sshattacker.core.crypto.packet.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.protocol.packet.BlobPacket;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobPacketPreparator extends AbstractPacketPreparator<BlobPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AbstractPacketEncryptor encryptor;

    public BlobPacketPreparator(
            Chooser chooser, BlobPacket packet, AbstractPacketEncryptor encryptor) {
        super(chooser, packet);
        this.encryptor = encryptor;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing BlobPacket");
        encrypt();
    }

    public void encrypt() {
        LOGGER.debug("Encrypting BlobPacket");
        encryptor.encrypt(getObject());
    }
}
