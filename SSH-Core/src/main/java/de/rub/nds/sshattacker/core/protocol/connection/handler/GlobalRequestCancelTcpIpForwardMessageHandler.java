/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelTcpIpForwardMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestCancelTcpIpForwardMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestCancelTcpIpForwardMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestCancelTcpIpForwardMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestCancelTcpIpForwardMessageHandler
        extends SshMessageHandler<GlobalRequestCancelTcpIpForwardMessage> {

    public GlobalRequestCancelTcpIpForwardMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestCancelTcpIpForwardMessageHandler(
            SshContext context, GlobalRequestCancelTcpIpForwardMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public GlobalRequestCancelTcpIpForwardMessageParser getParser(byte[] array) {
        return new GlobalRequestCancelTcpIpForwardMessageParser(array);
    }

    @Override
    public GlobalRequestCancelTcpIpForwardMessageParser getParser(byte[] array, int startPosition) {
        return new GlobalRequestCancelTcpIpForwardMessageParser(array, startPosition);
    }

    public static final GlobalRequestCancelTcpIpForwardMessagePreparator PREPARATOR =
            new GlobalRequestCancelTcpIpForwardMessagePreparator();

    @Override
    public GlobalRequestCancelTcpIpForwardMessageSerializer getSerializer() {
        return new GlobalRequestCancelTcpIpForwardMessageSerializer(message);
    }
}
