/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenSessionMessagePreperator
        extends ChannelOpenMessagePreparator<ChannelOpenSessionMessage> {
    public ChannelOpenSessionMessagePreperator(Chooser chooser, ChannelOpenSessionMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareChannelOpenMessageSpecificContents() {
        // TODO: I think it would be better to do this in ChannelOpenMessagePreparator, and pass
        //  ChannelType as argument
        // Always set correct channel type -> Don't use soft set
        channel.setChannelType(ChannelType.SESSION);
        object.setChannelType(channel.getChannelType(), true);
    }
}
