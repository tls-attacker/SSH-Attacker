/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestUnknownMessageHandler
        extends ChannelRequestMessageHandler<ChannelRequestUnknownMessage> {

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
