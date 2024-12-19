/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.preparator;

import de.rub.nds.sshattacker.core.data.packet.DataPacket;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DataPacketPreparator extends AbstractDataPacketPreparator<DataPacket> {

    public DataPacketPreparator(Chooser chooser, DataPacket dataPacket) {
        super(chooser, dataPacket);
    }

    @Override
    public void prepare() {
        object.setLength(object.getPayload().getValue().length);
    }
}
