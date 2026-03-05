/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestShellMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestShellMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestShellMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestShellMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestShellMessageHandler
        extends ChannelRequestMessageHandler<ChannelRequestShellMessage> {

    @Override
    public ChannelRequestShellMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestShellMessageParser(array);
    }

    @Override
    public ChannelRequestShellMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestShellMessageParser(array, startPosition);
    }

    public static final ChannelRequestShellMessagePreparator PREPARATOR =
            new ChannelRequestShellMessagePreparator();

    public static final ChannelRequestShellMessageSerializer SERIALIZER =
            new ChannelRequestShellMessageSerializer();
}
