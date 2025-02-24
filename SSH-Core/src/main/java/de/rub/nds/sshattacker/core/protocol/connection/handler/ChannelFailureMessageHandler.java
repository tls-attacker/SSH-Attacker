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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelFailureMessageHandler extends SshMessageHandler<ChannelFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, ChannelFailureMessage object) {
        Integer recipientChannelId = object.getRecipientChannelId().getValue();
        Channel channel = context.getChannelManager().getChannelByLocalId(recipientChannelId);
        if (channel != null) {
            // Remove the failed request from the queue
            if (channel.removeFirstSentRequestThatWantReply() == null) {
                LOGGER.warn(
                        "{} received but no channel request was send before on channel with id {}.",
                        object.getClass().getSimpleName(),
                        object.getRecipientChannelId().getValue());
            }
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring it.",
                    object.getClass().getSimpleName(),
                    object.getRecipientChannelId().getValue());
        }
    }

    @Override
    public ChannelFailureMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelFailureMessageParser(array);
    }

    @Override
    public ChannelFailureMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelFailureMessageParser(array, startPosition);
    }

    public static final ChannelFailureMessagePreparator PREPARATOR =
            new ChannelFailureMessagePreparator();

    public static final ChannelMessageSerializer<ChannelFailureMessage> SERIALIZER =
            new ChannelMessageSerializer<>();
}
