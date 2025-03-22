/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.preparator;

import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobPacketPreparator extends AbstractPacketPreparator<BlobPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void preparePacketContents(BlobPacket object, Chooser chooser) {
        LOGGER.debug("Compressing blob packet");
        chooser.getContext().getPacketLayer().getCompressor().compress(object);
        LOGGER.debug("Encrypting BlobPacket");
        chooser.getContext().getPacketLayer().getEncryptor().encrypt(object);
    }
}
