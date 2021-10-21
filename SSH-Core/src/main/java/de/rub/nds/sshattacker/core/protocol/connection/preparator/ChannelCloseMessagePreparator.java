/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelCloseMessagePreparator extends SshMessagePreparator<ChannelCloseMessage> {

    public ChannelCloseMessagePreparator(SshContext context, ChannelCloseMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_CLOSE);
        // TODO dummy values for fuzzing
        getObject().setRecipientChannel(Integer.MAX_VALUE);
    }
}
