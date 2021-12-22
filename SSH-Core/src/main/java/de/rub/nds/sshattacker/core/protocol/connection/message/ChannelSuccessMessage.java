/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelSuccessMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelSuccessMessage extends ChannelMessage<ChannelSuccessMessage> {

    public ChannelSuccessMessage() {
        super(MessageIDConstant.SSH_MSG_CHANNEL_SUCCESS);
    }

    public ChannelSuccessMessage(Integer senderChannel) {
        super(MessageIDConstant.SSH_MSG_CHANNEL_SUCCESS, senderChannel);
    }

    @Override
    public ChannelSuccessMessageHandler getHandler(SshContext context) {
        return new ChannelSuccessMessageHandler(context, this);
    }
}
