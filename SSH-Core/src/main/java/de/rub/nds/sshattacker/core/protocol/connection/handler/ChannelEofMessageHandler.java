/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelEofMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelEofMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelEofMessageHandler extends SshMessageHandler<ChannelEofMessage> {

    public ChannelEofMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelEofMessageHandler(SshContext context, ChannelEofMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelEofMessage
    }

    @Override
    public ChannelEofMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelEofMessageParser(array, startPosition);
    }

    @Override
    public ChannelEofMessagePreparator getPreparator() {
        return new ChannelEofMessagePreparator(context.getChooser(), message);
    }

    public ChannelEofMessagePreparator getChannelPreparator(Integer senderChannel) {
        return new ChannelEofMessagePreparator(context.getChooser(), message, senderChannel);
    }

    @Override
    public ChannelMessageSerializer<ChannelEofMessage> getSerializer() {
        return new ChannelMessageSerializer<>(message);
    }
}
