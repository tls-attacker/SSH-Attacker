/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenX11Message;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenX11MessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenX11Message> {

    public ChannelOpenX11MessagePreparator(Chooser chooser, ChannelOpenX11Message message) {
        super(chooser, message);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents() {
        // TODO: Replace dummy values
        getObject().setOriginatorAddress("192.168.7.38", true);
        getObject().setOriginatorPort(6000);
    }
}
