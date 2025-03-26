/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenConfirmationMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenConfirmationMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenConfirmationMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageHandler
        extends SshMessageHandler<ChannelOpenConfirmationMessage> {

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
        Channel channel = context.getChannels().get(message.getRecipientChannelId().getValue());
        if (channel == null) {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, creating a new channel from defaults with given channel id.",
                    getClass().getSimpleName(),
                    message.getRecipientChannelId().getValue());
            channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
            channel.setLocalChannelId(message.getRecipientChannelId().getValue());
            context.getChannels().put(channel.getLocalChannelId().getValue(), channel);
        }

        channel.setRemoteChannelId(message.getSenderChannelId());
        channel.setRemotePacketSize(message.getMaximumPacketSize());
        channel.setRemoteWindowSize(message.getInitialWindowSize());
        channel.setOpen(true);
    }

    @Override
    public ChannelOpenConfirmationMessageParser getParser(byte[] array) {
        return new ChannelOpenConfirmationMessageParser(array);
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
    public ChannelOpenConfirmationMessageSerializer getSerializer() {
        return new ChannelOpenConfirmationMessageSerializer(message);
    }
}
