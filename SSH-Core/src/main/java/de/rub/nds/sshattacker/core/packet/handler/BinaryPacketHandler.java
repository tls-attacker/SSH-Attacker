/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;

public class BinaryPacketHandler extends AbstractPacketHandler<BinaryPacket> {

    public BinaryPacketHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(BinaryPacket object) {}
}
