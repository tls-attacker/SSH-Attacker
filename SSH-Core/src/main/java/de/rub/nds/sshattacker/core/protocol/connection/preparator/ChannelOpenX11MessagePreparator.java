/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenX11Message;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenX11MessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenX11Message> {

    public ChannelOpenX11MessagePreparator() {
        super(ChannelType.X11);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents(
            ChannelOpenX11Message object, Chooser chooser) {
        // TODO: Replace dummy values
        object.setOriginatorAddress("192.168.7.38", true);
        object.setOriginatorPort(6000);
    }
}
