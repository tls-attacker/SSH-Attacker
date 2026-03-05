/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.constants.OpenSshTunnelMode;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenTunOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenTunOpenSshMessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenTunOpenSshMessage> {

    public ChannelOpenTunOpenSshMessagePreparator() {
        super(ChannelType.TUN_OPENSSH_COM);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents(
            ChannelOpenTunOpenSshMessage object, Chooser chooser) {
        // TODO: Replace dummy values
        object.setTunnelMode(OpenSshTunnelMode.SSH_TUNMODE_POINTTOPOINT);
        object.setRemoteUnitNumber(0);
    }
}
