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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitStatusMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestExitStatusMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestExitStatusMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestExitStatusMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestExitStatusMessageHandler
        extends SshMessageHandler<ChannelRequestExitStatusMessage>
        implements MessageSentHandler<ChannelRequestExitStatusMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelRequestExitStatusMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addReceivedRequestThatWantsReply(object);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, ChannelRequestExitStatusMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addSentRequestThatWantsReply(object);
        }
    }

    @Override
    public ChannelRequestExitStatusMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestExitStatusMessageParser(array);
    }

    @Override
    public ChannelRequestExitStatusMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestExitStatusMessageParser(array, startPosition);
    }

    public static final ChannelRequestExitStatusMessagePreparator PREPARATOR =
            new ChannelRequestExitStatusMessagePreparator();

    public static final ChannelRequestExitStatusMessageSerializer SERIALIZER =
            new ChannelRequestExitStatusMessageSerializer();
}
