/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.preparator;

import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class AbstractPacketPreparator<T extends AbstractPacket> extends Preparator<T> {

    public AbstractPacketPreparator(Chooser chooser, T object) {
        super(chooser, object);
    }
}
