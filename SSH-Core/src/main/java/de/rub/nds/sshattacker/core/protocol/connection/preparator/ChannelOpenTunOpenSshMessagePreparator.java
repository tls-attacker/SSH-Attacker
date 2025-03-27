/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.OpenSshTunnelMode;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenTunOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenTunOpenSshMessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenTunOpenSshMessage> {

    public ChannelOpenTunOpenSshMessagePreparator(
            Chooser chooser, ChannelOpenTunOpenSshMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents() {
        // TODO: Replace dummy values
        getObject().setTunnelMode(OpenSshTunnelMode.SSH_TUNMODE_POINTTOPOINT);
        getObject().setRemoteUnitNumber(0);
    }
}
