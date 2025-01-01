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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestUnknownMessageHandler
        extends SshMessageHandler<ChannelRequestUnknownMessage>
        implements MessageSentHandler<ChannelRequestUnknownMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelRequestUnknownMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addReceivedRequestThatWantsReply(object);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, ChannelRequestUnknownMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addSentRequestThatWantsReply(object);
        }
    }

    @Override
    public ChannelRequestUnknownMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestUnknownMessageParser(array);
    }

    @Override
    public ChannelRequestUnknownMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestUnknownMessageParser(array, startPosition);
    }

    public static final ChannelRequestUnknownMessagePreparator PREPARATOR =
            new ChannelRequestUnknownMessagePreparator();

    public static final ChannelRequestUnknownMessageSerializer SERIALIZER =
            new ChannelRequestUnknownMessageSerializer();
}
