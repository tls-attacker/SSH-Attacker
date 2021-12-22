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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenConfirmationMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenConfirmationMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenConfirmationMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.action.MessageAction;

public class ChannelOpenConfirmationMessageHandler
        extends SshMessageHandler<ChannelOpenConfirmationMessage> {

    public ChannelOpenConfirmationMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenConfirmationMessageHandler(
            SshContext context, ChannelOpenConfirmationMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // ToDo Handle ChannelOpenConfirmation
        Channel channel = MessageAction.getChannels().get(message.getRecipientChannel().getValue());
        if (channel == null) {
            throw new MissingChannelException(
                    "Can't find the required channel of the received message!");
        } else {
            channel.setRemoteChannel(message.getSenderChannel());
            channel.setRemotePacketSize(message.getPacketSize());
            channel.setRemoteWindowSize(message.getWindowSize());
            channel.setOpen(true);
            LOGGER.debug(channel.toString());
            Channel.getLocal_remote()
                    .put(
                            message.getRecipientChannel().getValue(),
                            message.getSenderChannel().getValue());
        }
    }

    @Override
    public ChannelOpenConfirmationMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenConfirmationMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenConfirmationMessagePreparator getPreparator() {
        return new ChannelOpenConfirmationMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenConfirmationMessagePreparator getChannelPreparator(Integer senderChannel) {
        return new ChannelOpenConfirmationMessagePreparator(
                context.getChooser(), message, senderChannel);
    }

    @Override
    public ChannelOpenConfirmationMessageSerializer getSerializer() {
        return new ChannelOpenConfirmationMessageSerializer(message);
    }
}
