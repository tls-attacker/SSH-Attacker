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

    @Override
    public void adjustContext(SshContext context, GlobalRequestCancelTcpIpForwardMessage object) {}

    @Override
    public GlobalRequestCancelTcpIpForwardMessageParser getParser(
            byte[] array, SshContext context) {
        return new GlobalRequestCancelTcpIpForwardMessageParser(array);
    }

    @Override
    public GlobalRequestCancelTcpIpForwardMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new GlobalRequestCancelTcpIpForwardMessageParser(array, startPosition);
    }

    public static final GlobalRequestCancelTcpIpForwardMessagePreparator PREPARATOR =
            new GlobalRequestCancelTcpIpForwardMessagePreparator();

    public static final GlobalRequestCancelTcpIpForwardMessageSerializer SERIALIZER =
            new GlobalRequestCancelTcpIpForwardMessageSerializer();
}
