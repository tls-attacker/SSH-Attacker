/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedStreamlocalOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenForwardedStreamlocalOpenSshMessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenForwardedStreamlocalOpenSshMessage> {

    public ChannelOpenForwardedStreamlocalOpenSshMessagePreparator(
            Chooser chooser, ChannelOpenForwardedStreamlocalOpenSshMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents() {
        // TODO: Replace dummy values
        getObject().setSocketPath("/var/run/sshattacker.sock", true);
        getObject().setReserved(new byte[0], true);
    }
}
