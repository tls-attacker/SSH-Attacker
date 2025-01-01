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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSignalMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestSignalMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestSignalMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestSignalMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestSignalMessageHandler
        extends SshMessageHandler<ChannelRequestSignalMessage>
        implements MessageSentHandler<ChannelRequestSignalMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelRequestSignalMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addReceivedRequestThatWantsReply(object);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, ChannelRequestSignalMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addSentRequestThatWantsReply(object);
        }
    }

    @Override
    public ChannelRequestSignalMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestSignalMessageParser(array);
    }

    @Override
    public ChannelRequestSignalMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestSignalMessageParser(array, startPosition);
    }

    public static final ChannelRequestSignalMessagePreparator PREPARATOR =
            new ChannelRequestSignalMessagePreparator();

    public static final ChannelRequestSignalMessageSerializer SERIALIZER =
            new ChannelRequestSignalMessageSerializer();
}
