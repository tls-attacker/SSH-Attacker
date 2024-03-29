/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;

public class ChannelWindowAdjustMessageHandler
        extends SshMessageHandler<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ChannelWindowAdjustMessage message) {
        Channel channel = sshContext.getChannels().get(message.getRecipientChannelId().getValue());
        if (channel != null) {
            if (!channel.isOpen().getValue()) {
                LOGGER.warn(
                        "{} received but channel with id {} is not open, continuing anyway.",
                        getClass().getSimpleName(),
                        message.getRecipientChannelId().getValue());
            }
            channel.setRemoteWindowSize(
                    channel.getLocalWindowSize().getValue() + message.getBytesToAdd().getValue());
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, creating a new channel from defaults with given channel id.",
                    getClass().getSimpleName(),
                    message.getRecipientChannelId().getValue());
            channel = sshContext.getConfig().getChannelDefaults().newChannelFromDefaults();
            sshContext.getChannels().put(channel.getLocalChannelId().getValue(), channel);
        }
    }
}
