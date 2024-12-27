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
import de.rub.nds.sshattacker.core.protocol.connection.ChannelManager;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelCloseMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelCloseMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelCloseMessageHandler extends SshMessageHandler<ChannelCloseMessage>
        implements MessageSentHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelCloseMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelCloseMessageHandler(SshContext context, ChannelCloseMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        ChannelManager channelManager = context.getChannelManager();
        Integer recipientChannelId = message.getRecipientChannelId().getValue();
        Channel channel = channelManager.getChannelByLocalId(recipientChannelId);
        if (channel != null) {
            if (!channel.isOpen().getValue()) {
                LOGGER.warn(
                        "{} received but channel with id {} is not open, continuing anyway.",
                        getClass().getSimpleName(),
                        recipientChannelId);
            } else {
                channel.setCloseMessageReceived(true);
                if (!channel.isOpen().getValue()) {
                    channelManager.removeChannelByLocalId(recipientChannelId);
                }
            }
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring request to close the channel.",
                    getClass().getSimpleName(),
                    recipientChannelId);
        }
    }

    @Override
    public void adjustContextAfterMessageSent() {
        ChannelManager channelManager = context.getChannelManager();
        Integer recipientChannelId = message.getRecipientChannelId().getValue();
        Channel channel = channelManager.getChannelByRemoteId(recipientChannelId);
        if (channel != null) {
            channel.setCloseMessageSent(true);
            if (!channel.isOpen().getValue()) {
                channelManager.removeChannelByRemoteId(recipientChannelId);
            }
        } else {
            LOGGER.warn(
                    "{} sent but no channel with remote id {} found, ignoring request to close the channel.",
                    getClass().getSimpleName(),
                    recipientChannelId);
        }
    }

    @Override
    public ChannelCloseMessageParser getParser(byte[] array) {
        return new ChannelCloseMessageParser(array);
    }

    @Override
    public ChannelCloseMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelCloseMessageParser(array, startPosition);
    }

    public static final ChannelCloseMessagePreparator PREPARATOR =
            new ChannelCloseMessagePreparator();

    @Override
    public ChannelMessageSerializer<ChannelCloseMessage> getSerializer() {
        return new ChannelMessageSerializer<>(message);
    }
}
