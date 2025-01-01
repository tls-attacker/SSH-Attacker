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
        extends SshMessageHandler<ChannelRequestSubsystemMessage>
        implements MessageSentHandler<ChannelRequestSubsystemMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelRequestSubsystemMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addReceivedRequestThatWantsReply(object);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, ChannelRequestSubsystemMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addSentRequestThatWantsReply(object);
        }
    }

    @Override
    public ChannelRequestSubsystemMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestSubsystemMessageParser(array);
    }

    @Override
    public ChannelRequestSubsystemMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestSubsystemMessageParser(array, startPosition);
    }

    public static final ChannelRequestSubsystemMessagePreparator PREPARATOR =
            new ChannelRequestSubsystemMessagePreparator();

    public static final ChannelRequestSubsystemMessageSerializer SERIALIZER =
            new ChannelRequestSubsystemMessageSerializer();
}
