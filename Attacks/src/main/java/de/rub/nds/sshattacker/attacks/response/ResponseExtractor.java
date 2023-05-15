/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.response;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;

import java.util.List;

/** Extracts a server's response to an attack vector */
public final class ResponseExtractor {

    /**
     * @param state SSH state
     * @param action Action containing the server's answer
     * @return A response fingerprint with the messages received by action
     */
    public static ResponseFingerprint getFingerprint(State state, ReceivingAction action) {
        List<ProtocolMessage<?>> messageList = action.getReceivedMessages();
        SocketState socketState = extractSocketState(state);
        return new ResponseFingerprint(messageList, socketState);
    }

    /**
     * @param state SSH state
     * @return Response fingerprint containing the state's last receiving action
     */
    public static ResponseFingerprint getFingerprint(State state) {
        ReceivingAction action = state.getWorkflowTrace().getLastReceivingAction();
        return getFingerprint(state, action);
    }

    private static SocketState extractSocketState(State state) {
        if (state.getSshContext().getTransportHandler() instanceof ClientTcpTransportHandler) {
            return ((ClientTcpTransportHandler) state.getSshContext().getTransportHandler())
                    .getSocketState();
        } else {
            return null;
        }
    }

    private ResponseExtractor() {
        super();
    }
}
