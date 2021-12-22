/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.factory;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.workflow.action.MessageAction;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MessageActionFactory {

    public static MessageAction createAction(
            Config config,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEndType,
            ProtocolMessage<?>... protocolMessages) {
        return createAction(
                config,
                connection,
                sendingConnectionEndType,
                new ArrayList<>(Arrays.asList(protocolMessages)));
    }

    public static MessageAction createAction(
            Config config,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEndType,
            Integer senderChannel,
            ProtocolMessage<?>... protocolMessages) {
        return createAction(
                config,
                connection,
                sendingConnectionEndType,
                new ArrayList<>(Arrays.asList(protocolMessages)),
                senderChannel);
    }

    public static MessageAction createAction(
            Config config,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            List<ProtocolMessage<?>> protocolMessages) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(protocolMessages);
        } else {
            action = new ReceiveAction(protocolMessages);
        }
        action.setConnectionAlias(connection.getAlias());
        return action;
    }

    public static MessageAction createAction(
            Config config,
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            List<ProtocolMessage<?>> protocolMessages,
            Integer senderChannel) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(protocolMessages, senderChannel);
        } else {
            action = new ReceiveAction(protocolMessages);
        }
        action.setConnectionAlias(connection.getAlias());
        return action;
    }

    private MessageActionFactory() {}
}
