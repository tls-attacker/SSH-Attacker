/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectTcpIpMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenDirectTcpIpMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenDirectTcpIpMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenDirectTcpIpMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenDirectTcpIpMessageHandler
        extends SshMessageHandler<ChannelOpenDirectTcpIpMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelOpenDirectTcpIpMessage object) {
        // TODO: Handle ChannelOpenDirectTcpIpMessage
    }

    @Override
    public ChannelOpenDirectTcpIpMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelOpenDirectTcpIpMessageParser(array);
    }

    @Override
    public ChannelOpenDirectTcpIpMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelOpenDirectTcpIpMessageParser(array, startPosition);
    }

    public static final ChannelOpenDirectTcpIpMessagePreparator PREPARATOR =
            new ChannelOpenDirectTcpIpMessagePreparator();

    public static final ChannelOpenDirectTcpIpMessageSerializer SERIALIZER =
            new ChannelOpenDirectTcpIpMessageSerializer();
}
