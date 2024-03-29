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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelCloseMessageHandler extends SshMessageHandler<ChannelCloseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelCloseMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ChannelCloseMessage message) {
        Channel channel = sshContext.getChannels().get(message.getRecipientChannelId().getValue());
        if (channel != null) {
            if (!channel.isOpen().getValue()) {
                LOGGER.warn(
                        "{} received but channel with id {} is not open, continuing anyway.",
                        getClass().getSimpleName(),
                        message.getRecipientChannelId().getValue());
            } else {
                channel.setCloseMessageReceived(true);
                if (!channel.isOpen().getValue()) {
                    sshContext.getChannels().remove(message.getRecipientChannelId().getValue());
                }
            }
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring request to close the channel.",
                    getClass().getSimpleName(),
                    message.getRecipientChannelId().getValue());
        }
    }
}
