/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestTcpIpForwardMessage;

public class GlobalRequestTcpIpForwardMessageHandler
        extends SshMessageHandler<GlobalRequestTcpIpForwardMessage> {

    public GlobalRequestTcpIpForwardMessageHandler(SshContext context) {
        super(context);
    }

    /*public GlobalRequestTcpIpForwardMessageHandler(
            SshContext context, GlobalRequestTcpIpForwardMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(GlobalRequestTcpIpForwardMessage message) {}

    /*@Override
    public SshMessageParser<GlobalRequestTcpIpForwardMessage> getParser(byte[] array) {
        return new GlobalRequestTcpIpForwardMessageParser(array);
    }

    @Override
    public SshMessageParser<GlobalRequestTcpIpForwardMessage> getParser(
            byte[] array, int startPosition) {
        return new GlobalRequestTcpIpForwardMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<GlobalRequestTcpIpForwardMessage> getPreparator() {
        return new GlobalRequestTcpIpForwardMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<GlobalRequestTcpIpForwardMessage> getSerializer() {
        return new GlobalRequestTcpIpForwardMessageSerializer(message);
    }*/
}
