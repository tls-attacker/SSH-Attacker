/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.connection.InboundConnection;
import de.rub.nds.sshattacker.core.connection.OutboundConnection;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.workflow.action.*;

import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.annotation.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.xml.stream.XMLStreamException;

/** A wrapper class over a list of protocol expectedMessages. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class WorkflowTrace implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Copy a workflow trace.
     *
     * <p>TODO: This should be replaced by a better copy method. Using serialization is slow and
     * needs some additional "tweaks", i.e. we have to manually restore important fields marked as
     * XmlTransient. This problem arises because the classes are configured for nice JAXB output,
     * and not for copying/storing full objects.
     *
     * @param orig the original WorkflowTrace object to copy
     * @return a copy of the original WorkflowTrace
     */
    public static WorkflowTrace copy(WorkflowTrace orig) {
        WorkflowTrace copy;

        List<SshAction> origActions = orig.getSshActions();

        try {
            String origTraceStr = WorkflowTraceSerializer.write(orig);
            InputStream is =
                    new ByteArrayInputStream(origTraceStr.getBytes(StandardCharsets.UTF_8.name()));
            copy = WorkflowTraceSerializer.insecureRead(is);
        } catch (JAXBException | IOException | XMLStreamException ex) {
            throw new ConfigurationException("Could not copy workflow trace: " + ex);
        }

        List<SshAction> copiedActions = copy.getSshActions();
        for (int i = 0; i < origActions.size(); i++) {
            copiedActions
                    .get(i)
                    .setSingleConnectionWorkflow(origActions.get(i).isSingleConnectionWorkflow());
        }

        return copy;
    }

    @XmlElements(
            value = {
                @XmlElement(type = AliasedConnection.class, name = "AliasedConnection"),
                @XmlElement(type = InboundConnection.class, name = "InboundConnection"),
                @XmlElement(type = OutboundConnection.class, name = "OutboundConnection")
            })
    private List<AliasedConnection> connections = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElements(
            value = {
                @XmlElement(type = SendAction.class, name = "Send"),
                @XmlElement(type = ReceiveAction.class, name = "Receive"),
                @XmlElement(type = ActivateEncryptionAction.class, name = "ActivateEncryption"),
                @XmlElement(type = DeactivateEncryptionAction.class, name = "DeactivateEncryption"),
                @XmlElement(type = ChangePacketLayerAction.class, name = "ChangePacketLayer"),
                @XmlElement(type = ChangeCompressionAction.class, name = "ChangeCompression"),
                @XmlElement(type = DynamicKeyExchangeAction.class, name = "DynamicKeyExchange"),
                @XmlElement(type = SendMangerSecretAction.class, name = "SendMangerSecret"),
                @XmlElement(type = ForwardMessagesAction.class, name = "ForwardMessages"),
                @XmlElement(type = ProxyFilterMessagesAction.class, name = "ProxyFilterMessages")
            })
    private List<SshAction> sshActions = new ArrayList<>();

    private String name = null;
    private String description = null;

    public WorkflowTrace() {
        this.sshActions = new LinkedList<>();
    }

    public WorkflowTrace(List<AliasedConnection> cons) {
        this.connections = cons;
    }

    public void reset() {
        for (SshAction action : getSshActions()) {
            action.reset();
        }
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<SshAction> getSshActions() {
        return sshActions;
    }

    public void addSshAction(SshAction action) {
        sshActions.add(action);
    }

    public void addSshActions(SshAction... actions) {
        addSshActions(Arrays.asList(actions));
    }

    public void addSshActions(List<SshAction> actions) {
        for (SshAction action : actions) {
            addSshAction(action);
        }
    }

    public void addSshAction(int position, SshAction action) {
        sshActions.add(position, action);
    }

    public SshAction removeSshAction(int index) {
        return sshActions.remove(index);
    }

    public void setSshActions(List<SshAction> sshActions) {
        this.sshActions = sshActions;
    }

    public void setSshActions(SshAction... sshActions) {
        setSshActions(new ArrayList<>(Arrays.asList(sshActions)));
    }

    public List<AliasedConnection> getConnections() {
        return connections;
    }

    /**
     * Set connections of the workflow trace. Use only if you know what you are doing. Unless you
     * are manually configuring workflow traces (say for MiTM or unit tests), there shouldn't be any
     * need to call this method.
     *
     * @param connections new connection to use with this workflow trace
     */
    public void setConnections(List<AliasedConnection> connections) {
        this.connections = connections;
    }

    /**
     * Add a connection to the workflow trace. Use only if you know what you are doing. Unless you
     * are manually configuring workflow traces (say for MiTM or unit tests), there shouldn't be any
     * need to call this method.
     *
     * @param connection new connection to add to the workflow trace
     */
    public void addConnection(AliasedConnection connection) {
        this.connections.add(connection);
    }

    public List<MessageAction> getMessageActions() {
        List<MessageAction> messageActions = new LinkedList<>();
        for (SshAction action : sshActions) {
            if (action instanceof MessageAction) {
                messageActions.add((MessageAction) action);
            }
        }
        return messageActions;
    }

    public List<ReceivingAction> getReceivingActions() {
        List<ReceivingAction> receiveActions = new LinkedList<>();
        for (SshAction action : sshActions) {
            if (action instanceof ReceivingAction) {
                receiveActions.add((ReceivingAction) action);
            }
        }
        return receiveActions;
    }

    public List<SendingAction> getSendingActions() {
        List<SendingAction> sendActions = new LinkedList<>();
        for (SshAction action : sshActions) {
            if (action instanceof SendingAction) {
                sendActions.add((SendingAction) action);
            }
        }
        return sendActions;
    }

    /**
     * Get the last SshAction of the workflow trace.
     *
     * @return the last SshAction of the workflow trace. Null if no actions are defined
     */
    public SshAction getLastAction() {
        int size = sshActions.size();
        if (size != 0) {
            return sshActions.get(size - 1);
        }
        return null;
    }

    /**
     * Get the last MessageAction of the workflow trace.
     *
     * @return the last MessageAction of the workflow trace. Null if no message actions are defined
     */
    public MessageAction getLastMessageAction() {
        for (int i = sshActions.size() - 1; i >= 0; i--) {
            if (sshActions.get(i) instanceof MessageAction) {
                return (MessageAction) (sshActions.get(i));
            }
        }
        return null;
    }

    /**
     * Get the last SendingAction of the workflow trace.
     *
     * @return the last SendingAction of the workflow trace. Null if no sending actions are defined
     */
    public SendingAction getLastSendingAction() {
        for (int i = sshActions.size() - 1; i >= 0; i--) {
            if (sshActions.get(i) instanceof SendingAction) {
                return (SendingAction) (sshActions.get(i));
            }
        }
        return null;
    }

    /**
     * Get the last ReceivingActionAction of the workflow trace.
     *
     * @return the last ReceivingActionAction of the workflow trace. Null if no receiving actions
     *     are defined
     */
    public ReceivingAction getLastReceivingAction() {
        for (int i = sshActions.size() - 1; i >= 0; i--) {
            if (sshActions.get(i) instanceof ReceivingAction) {
                return (ReceivingAction) (sshActions.get(i));
            }
        }
        return null;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Trace Actions:");
        for (SshAction action : sshActions) {
            sb.append("\n");
            sb.append(action.toString());
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 23 * hash + Objects.hashCode(this.sshActions);
        hash = 23 * hash + Objects.hashCode(this.name);
        hash = 23 * hash + Objects.hashCode(this.description);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final WorkflowTrace other = (WorkflowTrace) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        if (!Objects.equals(this.description, other.description)) {
            return false;
        }
        return Objects.equals(this.sshActions, other.sshActions);
    }

    public boolean executedAsPlanned() {
        for (SshAction action : sshActions) {
            if (!action.executedAsPlanned()) {
                LOGGER.debug("Action " + action.toCompactString() + " did not execute as planned");
                return false;
            } else {
                LOGGER.debug("Action " + action.toCompactString() + " executed as planned");
            }
        }
        return true;
    }

    public boolean allActionsExecuted() {
        for (SshAction action : sshActions) {
            if (!action.isExecuted()) {
                return false;
            }
        }
        return true;
    }
}
