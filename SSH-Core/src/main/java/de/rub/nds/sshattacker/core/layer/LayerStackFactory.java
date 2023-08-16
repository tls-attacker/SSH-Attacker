/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer;

import de.rub.nds.sshattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.context.TcpContext;
import de.rub.nds.sshattacker.core.layer.impl.*;
import de.rub.nds.sshattacker.core.state.Context;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Creates a layerStack based on pre-defined configurations. E.g., to send SSHv2 messages with
 * SSH-Attacker, we have to produce a layerStack that contains the SSHv2, TransportLayer, and
 * TcpLayer. Each layer is assigned a different context.
 */
public final class LayerStackFactory {
    private static final Logger LOGGER = LogManager.getLogger();

    public static LayerStack createLayerStack(LayerConfiguration type, Context context) {

        LOGGER.debug("Creating Layerstack for type: " + type);

        LayerStack layerStack;
        SshContext sshContext = context.getSshContext();
        TcpContext tcpContext = context.getTcpContext();

        switch (type) {
            case SSHV1:
                layerStack =
                        new LayerStack(
                                context,
                                new SSH1Layer(sshContext),
                                new PacketLayer(sshContext),
                                new TcpLayer(tcpContext));
                return layerStack;
            case SSHV2:
                layerStack =
                        new LayerStack(
                                context,
                                new SSH2Layer(sshContext),
                                new PacketLayer(sshContext),
                                new TcpLayer(tcpContext));
                return layerStack;
            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
