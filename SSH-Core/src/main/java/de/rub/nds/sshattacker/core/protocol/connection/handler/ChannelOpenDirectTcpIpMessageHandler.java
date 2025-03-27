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

    public ChannelOpenDirectTcpIpMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenDirectTcpIpMessageHandler(
            SshContext context, ChannelOpenDirectTcpIpMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelOpenDirectTcpIpMessage
    }

    @Override
    public ChannelOpenDirectTcpIpMessageParser getParser(byte[] array) {
        return new ChannelOpenDirectTcpIpMessageParser(array);
    }

    @Override
    public ChannelOpenDirectTcpIpMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenDirectTcpIpMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenDirectTcpIpMessagePreparator getPreparator() {
        return new ChannelOpenDirectTcpIpMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenDirectTcpIpMessageSerializer getSerializer() {
        return new ChannelOpenDirectTcpIpMessageSerializer(message);
    }
}
