/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestExecMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestExecMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestExecMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestExecMessageHandler
        extends ChannelRequestMessageHandler<ChannelRequestExecMessage> {

    @Override
    public ChannelRequestExecMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestExecMessageParser(array);
    }

    @Override
    public ChannelRequestExecMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestExecMessageParser(array, startPosition);
    }

    public static final ChannelRequestExecMessagePreparator PREPARATOR =
            new ChannelRequestExecMessagePreparator();

    public static final ChannelRequestExecMessageSerializer SERIALIZER =
            new ChannelRequestExecMessageSerializer();
}
