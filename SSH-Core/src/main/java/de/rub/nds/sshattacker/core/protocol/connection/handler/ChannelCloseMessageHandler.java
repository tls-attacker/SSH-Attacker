/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.connection.Channel;
import de.rub.nds.sshattacker.core.exceptions.MissingChannelException;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelCloseMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelCloseMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.action.MessageAction;

public class ChannelCloseMessageHandler extends SshMessageHandler<ChannelCloseMessage> {

    public ChannelCloseMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelCloseMessageHandler(SshContext context, ChannelCloseMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelCloseMessage
        Channel channel = MessageAction.getChannels().get(message.getRecipientChannel().getValue());
        if (channel == null) {
            throw new MissingChannelException(
                    "Can't find the required channel of the received message!");
        } else if (channel.isOpen().getValue()) {
            if (channel.getFirstCloseMessage().getValue()) {
                channel.setOpen(false);
            } else {
                channel.setFirstCloseMessage(true);
            }
        } else {
            throw new MissingChannelException("Required channel is closed!");
        }
    }

    @Override
    public ChannelCloseMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelCloseMessageParser(array, startPosition);
    }

    @Override
    public ChannelCloseMessagePreparator getPreparator() {
        return new ChannelCloseMessagePreparator(context.getChooser(), message);
    }

    public ChannelCloseMessagePreparator getChannelPreparator(Integer senderChannel) {
        return new ChannelCloseMessagePreparator(context.getChooser(), message, senderChannel);
    }

    @Override
    public ChannelMessageSerializer<ChannelCloseMessage> getSerializer() {
        return new ChannelMessageSerializer<>(message);
    }
}
