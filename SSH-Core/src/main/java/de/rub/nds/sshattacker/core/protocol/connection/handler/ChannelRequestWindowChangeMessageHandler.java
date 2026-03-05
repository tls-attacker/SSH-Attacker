/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestWindowChangeMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestWindowChangeMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestWindowChangeMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestWindowChangeMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestWindowChangeMessageHandler
        extends ChannelRequestMessageHandler<ChannelRequestWindowChangeMessage> {

    @Override
    public ChannelRequestWindowChangeMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestWindowChangeMessageParser(array);
    }

    @Override
    public ChannelRequestWindowChangeMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestWindowChangeMessageParser(array, startPosition);
    }

    public static final ChannelRequestWindowChangeMessagePreparator PREPARATOR =
            new ChannelRequestWindowChangeMessagePreparator();

    public static final ChannelRequestWindowChangeMessageSerializer SERIALIZER =
            new ChannelRequestWindowChangeMessageSerializer();
}
