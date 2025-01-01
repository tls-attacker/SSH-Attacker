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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitSignalMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestExitSignalMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestExitSignalMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestExitSignalMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestExitSignalMessageHandler
        extends SshMessageHandler<ChannelRequestExitSignalMessage>
        implements MessageSentHandler<ChannelRequestExitSignalMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelRequestExitSignalMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addReceivedRequestThatWantsReply(object);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, ChannelRequestExitSignalMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addSentRequestThatWantsReply(object);
        }
    }

    @Override
    public ChannelRequestExitSignalMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestExitSignalMessageParser(array);
    }

    @Override
    public ChannelRequestExitSignalMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestExitSignalMessageParser(array, startPosition);
    }

    public static final ChannelRequestExitSignalMessagePreparator PREPARATOR =
            new ChannelRequestExitSignalMessagePreparator();

    public static final ChannelRequestExitSignalMessageSerializer SERIALIZER =
            new ChannelRequestExitSignalMessageSerializer();
}
