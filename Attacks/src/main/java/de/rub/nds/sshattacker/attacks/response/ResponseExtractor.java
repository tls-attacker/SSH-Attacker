/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.response;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** */
public class ResponseExtractor {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * @param state
     * @param action
     * @return
     */
    public static ResponseFingerprint getFingerprint(State state, ReceivingAction action) {
        List<ProtocolMessage<?>> messageList = action.getReceivedMessages();
        SocketState socketState = extractSocketState(state);
        return new ResponseFingerprint(messageList, socketState);
    }

    /**
     * @param state
     * @return
     */
    public static ResponseFingerprint getFingerprint(State state) {
        ReceivingAction action = state.getWorkflowTrace().getLastReceivingAction();
        return getFingerprint(state, action);
    }

    private static SocketState extractSocketState(State state) {
        if (state.getSshContext().getTransportHandler() instanceof ClientTcpTransportHandler) {
            return (((ClientTcpTransportHandler) (state.getSshContext().getTransportHandler()))
                    .getSocketState());
        } else {
            return null;
        }
    }

    private static List<Class<ProtocolMessage<?>>> extractMessageClasses(ReceivingAction action) {
        List<Class<ProtocolMessage<?>>> classList = new LinkedList<>();
        if (action.getReceivedMessages() != null) {
            for (ProtocolMessage<?> message : action.getReceivedMessages()) {
                classList.add((Class<ProtocolMessage<?>>) message.getClass());
            }
        }
        return classList;
    }

    private ResponseExtractor() {}
}
