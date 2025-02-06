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
        extends SshMessageHandler<ChannelOpenConfirmationMessage>
        implements MessageSentHandler<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, ChannelOpenConfirmationMessage object) {
        ChannelManager channelManager = context.getChannelManager();
        Integer recipientChannelId = object.getRecipientChannelId().getValue();
        Integer senderChannelId = object.getSenderChannelId().getValue();

        Channel channel = channelManager.getPendingChannelByLocalId(recipientChannelId);
        if (channel == null) {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, creating a new channel from defaults with given channel id.",
                    object.getClass().getSimpleName(),
                    recipientChannelId);
            channel =
                    channelManager.createNewChannelFromDefaults(
                            recipientChannelId, senderChannelId);
        } else {
            channel.setRemoteChannelId(senderChannelId);
            channelManager.confirmPendingChannel(channel);
        }

        channel.setRemotePacketSize(object.getPacketSize());
        channel.setRemoteWindowSize(object.getWindowSize());
        channel.setOpen(true);
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, ChannelOpenConfirmationMessage object) {
        Integer localChannelId = object.getSenderChannelId().getValue();
        Channel cahnnel = context.getChannelManager().getChannelByLocalId(localChannelId);
        if (cahnnel != null) {
            // Channel is already added to the ChannelManager, just need to set it to open
            cahnnel.setOpen(true);
        } else {
            LOGGER.warn(
                    "{} sent but no channel with id {} found locally, ignoring request to confirm to open the channel.",
                    object.getClass().getSimpleName(),
                    localChannelId);
        }
    }

    @Override
    public ChannelOpenConfirmationMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelOpenConfirmationMessageParser(array);
    }

    @Override
    public ChannelOpenConfirmationMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelOpenConfirmationMessageParser(array, startPosition);
    }

    public static final ChannelOpenConfirmationMessagePreparator PREPARATOR =
            new ChannelOpenConfirmationMessagePreparator();

    public static final ChannelOpenConfirmationMessageSerializer SERIALIZER =
            new ChannelOpenConfirmationMessageSerializer();
}
