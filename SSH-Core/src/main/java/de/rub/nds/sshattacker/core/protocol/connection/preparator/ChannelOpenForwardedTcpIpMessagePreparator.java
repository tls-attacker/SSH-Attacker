/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedTcpIpMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenForwardedTcpIpMessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenForwardedTcpIpMessage> {

    public ChannelOpenForwardedTcpIpMessagePreparator() {
        super(ChannelType.FORWARDED_TCPIP);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents(
            ChannelOpenForwardedTcpIpMessage object, Chooser chooser) {
        // TODO: Replace dummy values
        object.setConnectedAddress("192.168.7.38", true);
        object.setConnectedPort(2200);
        object.setOriginatorAddress("192.168.7.39", true);
        object.setOriginatorPort(2201);
    }
}
