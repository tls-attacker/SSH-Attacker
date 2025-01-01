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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestAuthAgentMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestAuthAgentMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestAuthAgentMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestAuthAgentMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestAuthAgentMessageHandler
        extends SshMessageHandler<ChannelRequestAuthAgentMessage>
        implements MessageSentHandler<ChannelRequestAuthAgentMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelRequestAuthAgentMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addReceivedRequestThatWantsReply(object);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, ChannelRequestAuthAgentMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addSentRequestThatWantsReply(object);
        }
    }

    @Override
    public ChannelRequestAuthAgentMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestAuthAgentMessageParser(array);
    }

    @Override
    public ChannelRequestAuthAgentMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestAuthAgentMessageParser(array, startPosition);
    }

    public static final ChannelRequestAuthAgentMessagePreparator PREPARATOR =
            new ChannelRequestAuthAgentMessagePreparator();

    public static final ChannelRequestAuthAgentMessageSerializer SERIALIZER =
            new ChannelRequestAuthAgentMessageSerializer();
}
