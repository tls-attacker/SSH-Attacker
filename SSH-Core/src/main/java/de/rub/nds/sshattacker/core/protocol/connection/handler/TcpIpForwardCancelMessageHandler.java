/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.TcpIpForwardCancelMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.TcpIpForwardCancelMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.TcpIpForwardCancelMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.TcpIpForwardCancelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class TcpIpForwardCancelMessageHandler extends SshMessageHandler<TcpIpForwardCancelMessage> {

    public TcpIpForwardCancelMessageHandler(SshContext context) {
        super(context);
    }

    public TcpIpForwardCancelMessageHandler(SshContext context, TcpIpForwardCancelMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public SshMessageParser<TcpIpForwardCancelMessage> getParser(byte[] array, int startPosition) {
        return new TcpIpForwardCancelMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<TcpIpForwardCancelMessage> getPreparator() {
        return new TcpIpForwardCancelMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<TcpIpForwardCancelMessage> getSerializer() {
        return new TcpIpForwardCancelMessageSerializer(message);
    }
}
