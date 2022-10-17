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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelWindowAdjustMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelWindowAdjustMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelWindowAdjustMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelWindowAdjustMessageHandler
        extends SshMessageHandler<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelWindowAdjustMessageHandler(
            SshContext context, ChannelWindowAdjustMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        Channel channel = context.getChannels().get(message.getRecipientChannelId().getValue());
        if (channel != null) {
            if (!channel.isOpen().getValue()) {
                LOGGER.warn(
                        "{} received but channel with id {} is not open, continuing anyway.",
                        this.getClass().getSimpleName(),
                        message.getRecipientChannelId().getValue());
            }
            channel.setRemoteWindowSize(
                    channel.getLocalWindowSize().getValue() + message.getBytesToAdd().getValue());
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, creating a new channel from defaults with given channel id.",
                    this.getClass().getSimpleName(),
                    message.getRecipientChannelId().getValue());
            channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
            context.getChannels().put(channel.getLocalChannelId().getValue(), channel);
        }
    }

    @Override
    public ChannelWindowAdjustMessageParser getParser(byte[] array) {
        return new ChannelWindowAdjustMessageParser(array);
    }

    @Override
    public ChannelWindowAdjustMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelWindowAdjustMessageParser(array, startPosition);
    }

    @Override
    public ChannelWindowAdjustMessagePreparator getPreparator() {
        return new ChannelWindowAdjustMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelWindowAdjustMessageSerializer getSerializer() {
        return new ChannelWindowAdjustMessageSerializer(message);
    }
}
