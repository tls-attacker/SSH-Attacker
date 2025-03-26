/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedTcpIpMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenForwardedTcpIpMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenForwardedTcpIpMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenForwardedTcpIpMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenForwardedTcpIpMessageHandler
        extends SshMessageHandler<ChannelOpenForwardedTcpIpMessage> {

    public ChannelOpenForwardedTcpIpMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenForwardedTcpIpMessageHandler(
            SshContext context, ChannelOpenForwardedTcpIpMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public ChannelOpenForwardedTcpIpMessageParser getParser(byte[] array) {
        return new ChannelOpenForwardedTcpIpMessageParser(array);
    }

    @Override
    public ChannelOpenForwardedTcpIpMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenForwardedTcpIpMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenForwardedTcpIpMessagePreparator getPreparator() {
        return new ChannelOpenForwardedTcpIpMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenForwardedTcpIpMessageSerializer getSerializer() {
        return new ChannelOpenForwardedTcpIpMessageSerializer(message);
    }
}
