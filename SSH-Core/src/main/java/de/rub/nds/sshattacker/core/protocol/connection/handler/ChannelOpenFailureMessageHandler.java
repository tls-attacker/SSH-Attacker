/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelManager;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenFailureMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenFailureMessageHandler extends SshMessageHandler<ChannelOpenFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenFailureMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenFailureMessageHandler(SshContext context, ChannelOpenFailureMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        ChannelManager channelManager = context.getChannelManager();
        if (!channelManager.containsPendingChannelWithLocalId(
                message.getRecipientChannelId().getValue())) {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring it.",
                    message.getClass().getSimpleName(),
                    message.getRecipientChannelId().getValue());
        }
        channelManager.removePendingChannelByLocalId(message.getRecipientChannelId().getValue());
    }

    @Override
    public ChannelOpenFailureMessageParser getParser(byte[] array) {
        return new ChannelOpenFailureMessageParser(array);
    }

    @Override
    public ChannelOpenFailureMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenFailureMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenFailureMessagePreparator getPreparator() {
        return new ChannelOpenFailureMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenFailureMessageSerializer getSerializer() {
        return new ChannelOpenFailureMessageSerializer(message);
    }
}
