/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.PacketLayerType;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.packet.layer.PacketLayerFactory;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;

import jakarta.xml.bind.annotation.XmlAttribute;

public class ChangePacketLayerAction extends ConnectionBoundAction {

    @XmlAttribute(name = "to")
    protected PacketLayerType packetLayerType;

    protected Boolean enableAsciiMode = false;

    @SuppressWarnings("unused")
    private ChangePacketLayerAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public ChangePacketLayerAction(PacketLayerType packetLayerType) {
        this(
                AliasedConnection.DEFAULT_CONNECTION_ALIAS,
                packetLayerType,
                packetLayerType == PacketLayerType.BLOB);
    }

    public ChangePacketLayerAction(PacketLayerType packetLayerType, boolean enableAsciiMode) {
        this(AliasedConnection.DEFAULT_CONNECTION_ALIAS, packetLayerType, enableAsciiMode);
    }

    public ChangePacketLayerAction(String connectionAlias, PacketLayerType packetLayerType) {
        this(connectionAlias, packetLayerType, packetLayerType == PacketLayerType.BLOB);
    }

    public ChangePacketLayerAction(
            String connectionAlias, PacketLayerType packetLayerType, boolean enableAsciiMode) {
        super(connectionAlias);
        this.packetLayerType = packetLayerType;
        this.enableAsciiMode = enableAsciiMode;
    }

    /**
     * Get the type of packet layer that this action will change to.
     *
     * @return the new packet layer type
     */
    public PacketLayerType getPacketLayerType() {
        return packetLayerType;
    }

    /**
     * Get the "enable ascii mode" setting of this action.
     *
     * @return {@code true} if this action will enable ascii mode, else {@code false}
     */
    public boolean getEnableAsciiMode() {
        return enableAsciiMode;
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
        context.setReceiveAsciiModeEnabled(enableAsciiMode);
        setExecuted(true);
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
