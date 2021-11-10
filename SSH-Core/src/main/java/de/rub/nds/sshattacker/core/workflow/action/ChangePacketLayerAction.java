/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.PacketLayerType;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.packet.layer.PacketLayerFactory;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import javax.xml.bind.annotation.XmlAttribute;

public class ChangePacketLayerAction extends ConnectionBoundAction {

    @XmlAttribute(name = "to")
    protected PacketLayerType packetLayerType = null;

    protected ChangePacketLayerAction() {}

    public ChangePacketLayerAction(PacketLayerType packetLayerType) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.packetLayerType = packetLayerType;
    }

    public ChangePacketLayerAction(String connectionAlias, PacketLayerType packetLayerType) {
        super(connectionAlias);
        this.packetLayerType = packetLayerType;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (packetLayerType == null) {
            throw new WorkflowExecutionException(
                    "Unable to change packet layer, make sure to provide the packetLayerType element");
        }
        SshContext context = state.getSshContext(getConnectionAlias());
        context.setPacketLayerType(packetLayerType);
        context.setPacketLayer(PacketLayerFactory.getPacketLayer(packetLayerType, context));
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
