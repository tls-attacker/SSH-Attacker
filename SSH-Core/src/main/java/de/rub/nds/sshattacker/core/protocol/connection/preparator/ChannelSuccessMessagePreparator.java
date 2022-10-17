/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelSuccessMessagePreparator
        extends ChannelMessagePreparator<ChannelSuccessMessage> {

    public ChannelSuccessMessagePreparator(Chooser chooser, ChannelSuccessMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_SUCCESS);
    }

    @Override
    public void prepareChannelMessageSpecificContents() {}
}
