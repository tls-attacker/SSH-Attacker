/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelCloseMessagePreparator extends ChannelMessagePreparator<ChannelCloseMessage> {

    public ChannelCloseMessagePreparator(Chooser chooser, ChannelCloseMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_CLOSE);
    }

    @Override
    protected void prepareChannelMessageSpecificContents() {}
}
