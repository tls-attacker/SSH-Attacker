/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestSubsystemMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestSubsystemMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestSubsystemMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestSubsystemMessageHandler
        extends SshMessageHandler<ChannelRequestSubsystemMessage> {
    public ChannelRequestSubsystemMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestSubsystemMessageHandler(
            SshContext context, ChannelRequestSubsystemMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelRequestSubsystemMessage
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
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

    @Override
    public ChannelRequestSubsystemMessagePreparator getPreparator() {
        return new ChannelRequestSubsystemMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestSubsystemMessageSerializer getSerializer() {
        return new ChannelRequestSubsystemMessageSerializer(message);
    }
}
