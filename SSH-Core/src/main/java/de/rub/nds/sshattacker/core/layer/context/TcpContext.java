/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.context;

import de.rub.nds.sshattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.socket.SocketState;

/** Holds all runtime variables of the TCPLayer. */
public class TcpContext extends LayerContext {

    private SocketState finalSocketState;

    public TcpContext(Context context) {
        super(context);
        context.setTcpContext(this);
    }

    public SocketState getFinalSocketState() {
        return finalSocketState;
    }

    public void setFinalSocketState(SocketState finalSocketState) {
        this.finalSocketState = finalSocketState;
    }
}
