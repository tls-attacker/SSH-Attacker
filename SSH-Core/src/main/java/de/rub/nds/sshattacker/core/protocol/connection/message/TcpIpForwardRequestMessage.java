/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.TcpIpForwardRequestMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class TcpIpForwardRequestMessage extends TcpIpForwardMessage<TcpIpForwardRequestMessage> {

    public TcpIpForwardRequestMessage() {
        super(GlobalRequestType.TCPIP_FORWARD);
    }

    @Override
    public TcpIpForwardRequestMessageHandler getHandler(SshContext context) {
        return new TcpIpForwardRequestMessageHandler(context, this);
    }
}
