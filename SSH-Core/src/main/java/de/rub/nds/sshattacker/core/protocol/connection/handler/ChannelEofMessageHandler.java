/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelManager;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelEofMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelEofMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelEofMessageHandler extends SshMessageHandler<ChannelEofMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, ChannelEofMessage object) {
        // The other side will no longer send something in this channel
        ChannelManager channelManager = context.getChannelManager();
        Integer recipientChannelId = object.getRecipientChannelId().getValue();
        Channel channel = channelManager.getChannelByLocalId(recipientChannelId);
        if (channel != null) {
            if (!channel.isOpen().getValue()) {
                LOGGER.warn(
                        "{} received but channel with id {} is not open.",
                        object.getClass().getSimpleName(),
                        recipientChannelId);
            } else {
                LOGGER.warn(
                        "{} received for channel with id {}",
                        object.getClass().getSimpleName(),
                        recipientChannelId);
                // TODO: set eofMessageReceived to true for the channel
                // TODO: add sent handler and if eof received and sent -> send close channel message
            }
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally.",
                    object.getClass().getSimpleName(),
                    recipientChannelId);
        }
    }

    @Override
    public ChannelEofMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelEofMessageParser(array);
    }

    @Override
    public ChannelEofMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new ChannelEofMessageParser(array, startPosition);
    }

    public static final ChannelEofMessagePreparator PREPARATOR = new ChannelEofMessagePreparator();

    public static final ChannelMessageSerializer<ChannelEofMessage> SERIALIZER =
            new ChannelMessageSerializer<>();
}
