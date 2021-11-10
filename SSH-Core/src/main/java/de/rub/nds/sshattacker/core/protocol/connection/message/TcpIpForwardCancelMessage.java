/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.TcpIpForwardCancelMessageHandler;
import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.state.SshContext;

public class TcpIpForwardCancelMessage extends TcpIpForwardMessage<TcpIpForwardCancelMessage> {

    public TcpIpForwardCancelMessage(){
        super(GlobalRequestType.CANCEL_TCPIP_FORWARD);
    }

    @Override
    public TcpIpForwardCancelMessageHandler getHandler(SshContext context) {
        return new TcpIpForwardCancelMessageHandler(context, this);
    }
}
