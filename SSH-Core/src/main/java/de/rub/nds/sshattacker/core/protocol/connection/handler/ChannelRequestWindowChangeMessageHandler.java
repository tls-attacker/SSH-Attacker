/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestWindowChangeMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestWindowChangeMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestWindowChangeMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestWindowChangeMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestWindowChangeMessageHandler
        extends SshMessageHandler<ChannelRequestWindowChangeMessage> {
    public ChannelRequestWindowChangeMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestWindowChangeMessageHandler(
            SshContext context, ChannelRequestWindowChangeMessage message) {
        super(context, message);
    }

    @Override
    public ChannelRequestWindowChangeMessageParser getParser(byte[] array) {
        return new ChannelRequestWindowChangeMessageParser(array);
    }

    @Override
    public ChannelRequestWindowChangeMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestWindowChangeMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestWindowChangeMessagePreparator getPreparator() {
        return new ChannelRequestWindowChangeMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestWindowChangeMessageSerializer getSerializer() {
        return new ChannelRequestWindowChangeMessageSerializer(message);
    }

    @Override
    public void adjustContext() {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }
}
