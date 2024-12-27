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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestExecMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestExecMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestExecMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestExecMessageHandler extends SshMessageHandler<ChannelRequestExecMessage>
        implements MessageSentHandler {

    public ChannelRequestExecMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestExecMessageHandler(SshContext context, ChannelRequestExecMessage message) {
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
    public ChannelRequestExecMessageParser getParser(byte[] array) {
        return new ChannelRequestExecMessageParser(array);
    }

    @Override
    public ChannelRequestExecMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestExecMessageParser(array, startPosition);
    }

    public static final ChannelRequestExecMessagePreparator PREPARATOR =
            new ChannelRequestExecMessagePreparator();

    @Override
    public ChannelRequestExecMessageSerializer getSerializer() {
        return new ChannelRequestExecMessageSerializer(message);
    }
}
