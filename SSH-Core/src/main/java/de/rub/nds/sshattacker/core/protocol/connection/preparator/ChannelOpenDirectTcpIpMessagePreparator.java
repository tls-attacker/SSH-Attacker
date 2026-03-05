/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectTcpIpMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenDirectTcpIpMessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenDirectTcpIpMessage> {

    public ChannelOpenDirectTcpIpMessagePreparator() {
        super(ChannelType.DIRECT_TCPIP);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents(
            ChannelOpenDirectTcpIpMessage object, Chooser chooser) {
        // TODO: Replace dummy values
        object.setHostToConnect("192.168.7.38", true);
        object.setPortToConnect(2200);
        object.setOriginatorAddress("192.168.7.39", true);
        object.setOriginatorPort(2201);
    }
}
