/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestTcpIpForwardMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestTcpIpForwardMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestTcpIpForwardMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestTcpIpForwardMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestTcpIpForwardMessageHandler
        extends SshMessageHandler<GlobalRequestTcpIpForwardMessage> {

    @Override
    public void adjustContext(SshContext context, GlobalRequestTcpIpForwardMessage object) {}

    @Override
    public GlobalRequestTcpIpForwardMessageParser getParser(byte[] array, SshContext context) {
        return new GlobalRequestTcpIpForwardMessageParser(array);
    }

    @Override
    public GlobalRequestTcpIpForwardMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new GlobalRequestTcpIpForwardMessageParser(array, startPosition);
    }

    public static final GlobalRequestTcpIpForwardMessagePreparator PREPARATOR =
            new GlobalRequestTcpIpForwardMessagePreparator();

    public static final GlobalRequestTcpIpForwardMessageSerializer SERIALIZER =
            new GlobalRequestTcpIpForwardMessageSerializer();
}
