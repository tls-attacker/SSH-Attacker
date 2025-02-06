/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.factory;

import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;

public final class SshActionFactory {

    private SshActionFactory() {
        super();
    }

    /**
     * Creates a Message Action with the receive options: IGNORE_CHANNEL_DATA_WRAPPER and
     * IGNORE_UNEXPECTED_CHANNEL_WINDOW_ADJUSTS
     */
    public static MessageAction createDataMessageAction(
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            ProtocolMessage<?>... dataMessages) {
        return createDataMessageAction(
                connection, sendingConnectionEnd, new ArrayList<>(Arrays.asList(dataMessages)));
    }

    /**
     * Creates a Message Action with the receive options: IGNORE_CHANNEL_DATA_WRAPPER and
     * IGNORE_UNEXPECTED_CHANNEL_WINDOW_ADJUSTS
     */
    public static MessageAction createDataMessageAction(
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            ArrayList<ProtocolMessage<?>> dataMessages) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(connection.getAlias(), dataMessages);
        } else {
            action = new ReceiveAction(connection.getAlias(), dataMessages);
            ((ReceiveAction) action)
                    .setReceiveOptions(
                            Set.of(
                                    ReceiveAction.ReceiveOption
                                            .IGNORE_UNEXPECTED_CHANNEL_WINDOW_ADJUSTS));
        }
        return action;
    }

    public static MessageAction createMessageAction(
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            ProtocolMessage<?>... protocolMessages) {
        return createMessageAction(
                connection, sendingConnectionEnd, new ArrayList<>(Arrays.asList(protocolMessages)));
    }

    public static MessageAction createMessageAction(
            AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd,
            ArrayList<ProtocolMessage<?>> protocolMessages) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(connection.getAlias(), protocolMessages);
        } else {
            action = new ReceiveAction(connection.getAlias(), protocolMessages);
        }
        return action;
    }

    public static MessageAction withReceiveOptions(
            MessageAction action, Set<ReceiveAction.ReceiveOption> receiveOptions) {
        if (action instanceof ReceiveAction) {
            ((ReceiveAction) action).setReceiveOptions(receiveOptions);
        }
        return action;
    }

    /**
     * Creates a ForwardAction for the provided protocolMessages. The order of inbound and
     * outboundConnection stays the same in the whole workflow. In this case the ConnectionEndType
     * specifies, from which party the message should be received to be forwarded.
     *
     * @param inboundConnection fixed inboundConnection (client to proxy/mitm)
     * @param outboundConnection fixed outboundConnection (proxy/mitm to server)
     * @param sendingConnectionEnd specifies on which connection the messages are received
     * @param protocolMessages messages to be sent
     * @return ForwardAction with the provided inputs
     */
    public static SshAction createForwardAction(
            AliasedConnection inboundConnection,
            AliasedConnection outboundConnection,
            ConnectionEndType sendingConnectionEnd,
            ProtocolMessage<?>... protocolMessages) {
        return createForwardAction(
                inboundConnection,
                outboundConnection,
                sendingConnectionEnd,
                new ArrayList<>(Arrays.asList(protocolMessages)));
    }

    /**
     * Creates a ForwardAction for the provided protocolMessages. The order of inbound and
     * outboundConnection stays the same in the whole workflow. In this case the ConnectionEndType
     * specifies, from which party the message should be received to be forwarded.
     *
     * @param inboundConnection fixed inboundConnection (client to proxy/mitm)
     * @param outboundConnection fixed outboundConnection (proxy/mitm to server)
     * @param sendingConnectionEnd specifies on which connection the messages are received
     * @param protocolMessages messages to be sent
     * @return ForwardAction with the provided inputs
     */
    public static SshAction createForwardAction(
            AliasedConnection inboundConnection,
            AliasedConnection outboundConnection,
            ConnectionEndType sendingConnectionEnd,
            ArrayList<ProtocolMessage<?>> protocolMessages) {
        ForwardMessagesAction action;
        if (sendingConnectionEnd == ConnectionEndType.CLIENT) {
            action =
                    new ForwardMessagesAction(
                            inboundConnection.getAlias(),
                            outboundConnection.getAlias(),
                            protocolMessages);
        } else {
            action =
                    new ForwardMessagesAction(
                            outboundConnection.getAlias(),
                            inboundConnection.getAlias(),
                            protocolMessages);
        }
        return action;
    }

    public static SshAction createProxyFilterMessagesAction(
            AliasedConnection inboundConnection,
            AliasedConnection outboundConnection,
            ConnectionEndType sendingConnectionEnd,
            ProtocolMessage<?>... protocolMessages) {
        return createProxyFilterMessagesAction(
                inboundConnection,
                outboundConnection,
                sendingConnectionEnd,
                new ArrayList<>(Arrays.asList(protocolMessages)));
    }

    public static SshAction createProxyFilterMessagesAction(
            AliasedConnection inboundConnection,
            AliasedConnection outboundConnection,
            ConnectionEndType sendingConnectionEnd,
            ArrayList<ProtocolMessage<?>> protocolMessages) {
        ProxyFilterMessagesAction action;
        if (sendingConnectionEnd == ConnectionEndType.CLIENT) {
            action =
                    new ProxyFilterMessagesAction(
                            inboundConnection.getAlias(),
                            outboundConnection.getAlias(),
                            protocolMessages);
        } else {
            action =
                    new ProxyFilterMessagesAction(
                            outboundConnection.getAlias(),
                            inboundConnection.getAlias(),
                            protocolMessages);
        }
        return action;
    }
}
