/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestBreakMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestBreakMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestBreakMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestBreakMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestBreakMessageHandler
        extends ChannelRequestMessageHandler<ChannelRequestBreakMessage> {

    @Override
    public ChannelRequestBreakMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestBreakMessageParser(array);
    }

    @Override
    public ChannelRequestBreakMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestBreakMessageParser(array, startPosition);
    }

    public static final ChannelRequestBreakMessagePreparator PREPARATOR =
            new ChannelRequestBreakMessagePreparator();

    public static final ChannelRequestBreakMessageSerializer SERIALIZER =
            new ChannelRequestBreakMessageSerializer();
}
