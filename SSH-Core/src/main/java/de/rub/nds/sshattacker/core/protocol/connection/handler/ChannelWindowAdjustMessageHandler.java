/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelWindowAdjustMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelWindowAdjustMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelWindowAdjustMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelWindowAdjustMessageHandler extends SshMessageHandler<ChannelWindowAdjustMessage>
        implements MessageSentHandler<ChannelWindowAdjustMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelWindowAdjustMessage object) {
        Integer recipientChannelId = object.getRecipientChannelId().getValue();
        Channel channel = context.getChannelManager().getChannelByLocalId(recipientChannelId);
        if (channel != null) {
            if (!channel.isOpen().getValue()) {
                LOGGER.warn(
                        "{} received but channel with id {} is not open, continuing anyway.",
                        getClass().getSimpleName(),
                        recipientChannelId);
            }
            channel.setRemoteWindowSize(
                    channel.getRemoteWindowSize().getValue() + object.getBytesToAdd().getValue());
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring request to adjust window of the channel.",
                    object.getClass().getSimpleName(),
                    recipientChannelId);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, ChannelWindowAdjustMessage object) {
        Integer recipientChannelId = object.getRecipientChannelId().getValue();
        Channel channel = context.getChannelManager().getChannelByRemoteId(recipientChannelId);
        if (channel != null) {
            channel.setLocalWindowSize(
                    channel.getLocalWindowSize().getValue() + object.getBytesToAdd().getValue());
        } else {
            LOGGER.warn(
                    "{} sent but no channel with remote id {} found, ignoring request to adjust window of the channel.",
                    object.getClass().getSimpleName(),
                    recipientChannelId);
        }
    }

    @Override
    public ChannelWindowAdjustMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelWindowAdjustMessageParser(array);
    }

    @Override
    public ChannelWindowAdjustMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelWindowAdjustMessageParser(array, startPosition);
    }

    public static final ChannelWindowAdjustMessagePreparator PREPARATOR =
            new ChannelWindowAdjustMessagePreparator();

    public static final ChannelWindowAdjustMessageSerializer SERIALIZER =
            new ChannelWindowAdjustMessageSerializer();
}
