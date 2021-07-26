/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelEofMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelEofMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelEofMessage extends ChannelMessage<ChannelEofMessage> {

    public ChannelEofMessage() {
        super(MessageIDConstant.SSH_MSG_CHANNEL_EOF);
    }

    @Override
    public ChannelEofMessageHandler getHandler(SshContext context) {
        return new ChannelEofMessageHandler(context);
    }

    @Override
    public ChannelMessageSerializer<ChannelEofMessage> getSerializer() {
        return new ChannelMessageSerializer<>(this);
    }

    @Override
    public ChannelEofMessagePreparator getPreparator(SshContext context) {
        return new ChannelEofMessagePreparator(context, this);
    }

}
