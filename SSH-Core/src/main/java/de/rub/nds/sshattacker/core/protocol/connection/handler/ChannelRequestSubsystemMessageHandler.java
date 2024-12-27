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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestSubsystemMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestSubsystemMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestSubsystemMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestSubsystemMessageHandler
        extends SshMessageHandler<ChannelRequestSubsystemMessage> implements MessageSentHandler {
    public ChannelRequestSubsystemMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestSubsystemMessageHandler(
            SshContext context, ChannelRequestSubsystemMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addReceivedRequestThatWantsReply(message);
        }
    }

    @Override
    public void adjustContextAfterMessageSent() {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addSentRequestThatWantsReply(message);
        }
    }

    @Override
    public ChannelRequestSubsystemMessageParser getParser(byte[] array) {
        return new ChannelRequestSubsystemMessageParser(array);
    }

    @Override
    public ChannelRequestSubsystemMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestSubsystemMessageParser(array, startPosition);
    }

    public static final ChannelRequestSubsystemMessagePreparator PREPARATOR =
            new ChannelRequestSubsystemMessagePreparator();

    @Override
    public ChannelRequestSubsystemMessageSerializer getSerializer() {
        return new ChannelRequestSubsystemMessageSerializer(message);
    }
}
