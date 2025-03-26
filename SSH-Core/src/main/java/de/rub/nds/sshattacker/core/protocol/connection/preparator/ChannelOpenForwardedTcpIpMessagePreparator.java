/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedTcpIpMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenForwardedTcpIpMessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenForwardedTcpIpMessage> {

    public ChannelOpenForwardedTcpIpMessagePreparator(
            Chooser chooser, ChannelOpenForwardedTcpIpMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents() {
        // TODO: Replace dummy values
        getObject().setConnectedAddress("192.168.7.38", true);
        getObject().setConnectedPort(2200);
        getObject().setOriginatorAddress("192.168.7.39", true);
        getObject().setOriginatorPort(2201);
    }
}
