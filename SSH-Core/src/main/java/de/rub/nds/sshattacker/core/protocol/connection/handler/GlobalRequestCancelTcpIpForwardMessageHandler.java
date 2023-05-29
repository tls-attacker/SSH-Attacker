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
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelTcpIpForwardMessage;

public class GlobalRequestCancelTcpIpForwardMessageHandler
        extends SshMessageHandler<GlobalRequestCancelTcpIpForwardMessage> {

    public GlobalRequestCancelTcpIpForwardMessageHandler(SshContext context) {
        super(context);
    }

    /*public GlobalRequestCancelTcpIpForwardMessageHandler(
            SshContext context, GlobalRequestCancelTcpIpForwardMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(GlobalRequestCancelTcpIpForwardMessage message) {}

    /*@Override
    public SshMessageParser<GlobalRequestCancelTcpIpForwardMessage> getParser(byte[] array) {
        return new GlobalRequestCancelTcpIpForwardMessageParser(array);
    }

    @Override
    public SshMessageParser<GlobalRequestCancelTcpIpForwardMessage> getParser(
            byte[] array, int startPosition) {
        return new GlobalRequestCancelTcpIpForwardMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<GlobalRequestCancelTcpIpForwardMessage> getPreparator() {
        return new GlobalRequestCancelTcpIpForwardlMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<GlobalRequestCancelTcpIpForwardMessage> getSerializer() {
        return new GlobalRequestCancelTcpIpForwardlMessageSerializer(message);
    }*/
}
