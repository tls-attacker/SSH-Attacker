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
        extends SshMessageHandler<ChannelRequestExitStatusMessage> implements MessageSentHandler {

    public ChannelRequestExitStatusMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestExitStatusMessageHandler(
            SshContext context, ChannelRequestExitStatusMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addReceivedRequestThatWantsReply(message);
        }
    }

    @Override
    public void adjustContextAfterMessageSent() {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addSentRequestThatWantsReply(message);
        }
    }

    @Override
    public ChannelRequestExitStatusMessageParser getParser(byte[] array) {
        return new ChannelRequestExitStatusMessageParser(array);
    }

    @Override
    public ChannelRequestExitStatusMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestExitStatusMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestExitStatusMessagePreparator getPreparator() {
        return new ChannelRequestExitStatusMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestExitStatusMessageSerializer getSerializer() {
        return new ChannelRequestExitStatusMessageSerializer(message);
    }
}
