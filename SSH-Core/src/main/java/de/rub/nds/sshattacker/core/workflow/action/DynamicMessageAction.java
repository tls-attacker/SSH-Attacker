/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public abstract class DynamicMessageAction extends MessageAction
        implements ReceivingAction, SendingAction {

    protected ArrayList<SshAction> sshActions = new ArrayList<>();

    protected DynamicMessageAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    protected DynamicMessageAction(String connectionAlias) {
        super(connectionAlias);
    }

    protected DynamicMessageAction(DynamicMessageAction other) {
        super(other);
        if (other.sshActions != null) {
            sshActions = new ArrayList<>(other.sshActions.size());
            for (SshAction item : other.sshActions) {
                sshActions.add(item != null ? item.createCopy() : null);
            }
        }
    }

    @Override
    public abstract DynamicMessageAction createCopy();

    @Override
    public List<ProtocolMessage<?>> getReceivedMessages() {
        return sshActions == null
                ? new ArrayList<>()
                : sshActions.stream()
                        .filter(action -> action instanceof ReceivingAction)
                        .flatMap(
                                action -> ((ReceivingAction) action).getReceivedMessages().stream())
                        .collect(Collectors.toList());
    }

    @Override
    public List<AbstractPacket> getReceivedPackets() {
        return sshActions == null
                ? new ArrayList<>()
                : sshActions.stream()
                        .filter(action -> action instanceof ReceivingAction)
                        .flatMap(action -> ((ReceivingAction) action).getReceivedPackets().stream())
                        .collect(Collectors.toList());
    }

    @Override
    public List<ProtocolMessage<?>> getSendMessages() {
        return sshActions == null
                ? new ArrayList<>()
                : sshActions.stream()
                        .filter(action -> action instanceof SendingAction)
                        .flatMap(action -> ((SendingAction) action).getSendMessages().stream())
                        .collect(Collectors.toList());
    }

    public List<SshAction> getSshActions() {
        return sshActions == null ? new ArrayList<>() : sshActions;
    }

    @Override
    public void reset(boolean resetModifiableVariables) {
        sshActions = new ArrayList<>();
        setExecuted(null);
    }

    @Override
    protected void stripEmptyLists() {
        super.stripEmptyLists();
        if (sshActions != null && sshActions.isEmpty()) {
            sshActions = null;
        }
    }

    @Override
    protected void initEmptyLists() {
        super.initEmptyLists();
        if (sshActions == null) {
            sshActions = new ArrayList<>();
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append(getClass().getSimpleName());
        if (!isExecuted()) {
            sb.append(": (not executed)\n");
        } else {
            sb.append(":");
        }
        sb.append("Dynamic Actions:\n");
        if (sshActions != null && !sshActions.isEmpty()) {
            for (SshAction sshAction : sshActions) {
                sb.append(sshAction.toString());
                sb.append("\n");
            }
        } else {
            sb.append("(no actions set)");
        }
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        // Return true if this action was executed and all contained ssh
        // actions were executed as planned.
        return isExecuted()
                && sshActions.stream()
                        .map(SshAction::executedAsPlanned)
                        .filter(Predicate.isEqual(false))
                        .findAny()
                        .isEmpty();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        if (!super.equals(obj)) return false;
        DynamicMessageAction that = (DynamicMessageAction) obj;
        return Objects.equals(sshActions, that.sshActions);
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 79 * hash + Objects.hash(super.hashCode(), sshActions);
        return hash;
    }
}
