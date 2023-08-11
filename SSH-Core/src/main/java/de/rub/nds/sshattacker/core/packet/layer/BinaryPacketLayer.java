/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.layer;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketLayer extends AbstractPacketLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    public BinaryPacketLayer(SshContext context) {
        super(context);
    }

    @Override
    protected void decryptPacket(AbstractPacket packet) {
        if (!(packet instanceof BinaryPacket)) {
            LOGGER.warn("Decrypting received non binary packet: {}", packet);
        }
        super.decryptPacket(packet);
    }
}
