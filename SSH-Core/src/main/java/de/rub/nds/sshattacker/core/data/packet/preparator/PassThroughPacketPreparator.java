/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.preparator;

import de.rub.nds.sshattacker.core.data.packet.PassThroughPacket;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class PassThroughPacketPreparator extends AbstractDataPacketPreparator<PassThroughPacket> {

    public PassThroughPacketPreparator(Chooser chooser, PassThroughPacket passThroughPacket) {
        super(chooser, passThroughPacket);
    }

    @Override
    public void prepare() {}
}
