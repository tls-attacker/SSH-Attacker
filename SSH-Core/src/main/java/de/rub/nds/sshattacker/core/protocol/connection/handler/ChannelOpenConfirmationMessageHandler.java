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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenConfirmationMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenConfirmationMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenConfirmationMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageHandler
        extends SshMessageHandler<ChannelOpenConfirmationMessage> implements MessageSentHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenConfirmationMessageHandler(
            SshContext context, ChannelOpenConfirmationMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        ChannelManager channelManager = context.getChannelManager();
        Integer recipientChannelId = message.getRecipientChannelId().getValue();
        Integer senderChannelId = message.getSenderChannelId().getValue();

        Channel channel = channelManager.getPendingChannelByLocalId(recipientChannelId);
        if (channel == null) {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, creating a new channel from defaults with given channel id.",
                    getClass().getSimpleName(),
                    recipientChannelId);
            channel =
                    channelManager.createNewChannelFromDefaults(
                            recipientChannelId, senderChannelId);
        } else {
            channel.setRemoteChannelId(senderChannelId);
            channelManager.confirmPendingChannel(channel);
        }

        channel.setRemotePacketSize(message.getPacketSize());
        channel.setRemoteWindowSize(message.getWindowSize());
        channel.setOpen(true);
    }

    @Override
    public void adjustContextAfterMessageSent() {
        Integer localChannelId = message.getSenderChannelId().getValue();
        Channel cahnnel = context.getChannelManager().getChannelByLocalId(localChannelId);
        if (cahnnel != null) {
            // Channel is already added to the ChannelManager, just need to set it to open
            cahnnel.setOpen(true);
        } else {
            LOGGER.warn(
                    "{} sent but no channel with id {} found locally, ignoring request to confirm to open the channel.",
                    getClass().getSimpleName(),
                    localChannelId);
        }
    }

    @Override
    public ChannelOpenConfirmationMessageParser getParser(byte[] array) {
        return new ChannelOpenConfirmationMessageParser(array);
    }

    @Override
    public ChannelOpenConfirmationMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenConfirmationMessageParser(array, startPosition);
    }

    public static final ChannelOpenConfirmationMessagePreparator PREPARATOR =
            new ChannelOpenConfirmationMessagePreparator();

    @Override
    public ChannelOpenConfirmationMessageSerializer getSerializer() {
        return new ChannelOpenConfirmationMessageSerializer(message);
    }
}
