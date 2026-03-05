/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
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

    @Override
    public void adjustContext(SshContext context, ChannelOpenFailureMessage object) {
        ChannelManager channelManager = context.getChannelManager();
        if (!channelManager.containsPendingChannelWithLocalId(
                object.getRecipientChannelId().getValue())) {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring it.",
                    object.getClass().getSimpleName(),
                    object.getRecipientChannelId().getValue());
        }
        channelManager.removePendingChannelByLocalId(object.getRecipientChannelId().getValue());
    }

    @Override
    public ChannelOpenFailureMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelOpenFailureMessageParser(array);
    }

    @Override
    public ChannelOpenFailureMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelOpenFailureMessageParser(array, startPosition);
    }

    public static final ChannelOpenFailureMessagePreparator PREPARATOR =
            new ChannelOpenFailureMessagePreparator();

    public static final ChannelOpenFailureMessageSerializer SERIALIZER =
            new ChannelOpenFailureMessageSerializer();
}
