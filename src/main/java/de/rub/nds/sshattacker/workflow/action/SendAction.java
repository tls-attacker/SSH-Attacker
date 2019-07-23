/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.sshattacker.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.protocol.ModifiableVariableHolder;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.Message;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.state.State;
import de.rub.nds.sshattacker.workflow.action.executor.MessageActionResult;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * todo print configured binaryPackets
 */
public class SendAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendAction() {
        super();
    }

    public SendAction(List<Message> messages) {
        super(messages);
    }

    public SendAction(Message... messages) {
        this(new ArrayList<>(Arrays.asList(messages)));
    }

    public SendAction(String connectionAlias) {
        super(connectionAlias);
    }

    public SendAction(String connectionAlias, List<Message> messages) {
        super(connectionAlias, messages);
    }

    public SendAction(String connectionAlias, Message... messages) {
        super(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext sshContext = state.getSshContext(connectionAlias);

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        String sending = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Sending messages: " + sending);
        } else {
            LOGGER.info("Sending messages (" + connectionAlias + "): " + sending);
        }

        try {
            MessageActionResult result = sendMessageHelper.sendMessages(messages, binaryPackets, sshContext);
            messages = new ArrayList<>(result.getMessageList());
            binaryPackets = new ArrayList<>(result.getBinaryPacketList());
            setExecuted(true);
        } catch (IOException E) {
            sshContext.setReceivedTransportHandlerException(true);
            LOGGER.debug(E);
            setExecuted(false);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Send Action:\n");
        } else {
            sb = new StringBuilder("Send Action: (not executed)\n");
        }
        sb.append("\tMessages:");
        if (messages != null) {
            for (Message message : messages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
            sb.append("\n");
        } else {
            sb.append("null (no messages set)");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        if ((messages != null) && (!messages.isEmpty())) {
            sb.append(" (");
            for (Message message : messages) {
                sb.append(message.toCompactString());
                sb.append(",");
            }
            sb.deleteCharAt(sb.lastIndexOf(",")).append(")");
        } else {
            sb.append(" (no messages set)");
        }
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void setBinaryPackets(List<BinaryPacket> records) {
        this.binaryPackets = records;
    }

    @Override
    public void reset() {
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        if (messages != null) {
            for (Message message : messages) {
                holders.addAll(message.getAllModifiableVariableHolders());
            }
        }
        if (getBinaryPackets() != null) {
            for (BinaryPacket binaryPacket : getBinaryPackets()) {
                holders.addAll(binaryPacket.getAllModifiableVariableHolders());
            }
        }
        for (ModifiableVariableHolder holder : holders) {
            List<Field> fields = holder.getAllModifiableVariableFields();
            for (Field f : fields) {
                f.setAccessible(true);

                ModifiableVariable mv = null;
                try {
                    mv = (ModifiableVariable) f.get(holder);
                } catch (IllegalArgumentException | IllegalAccessException ex) {
                    LOGGER.warn("Could not retrieve ModifiableVariables");
                    LOGGER.debug(ex);
                }
                if (mv != null) {
                    if (mv.getModification() != null || mv.isCreateRandomModification()) {
                        mv.setOriginalValue(null);
                    } else {
                        try {
                            f.set(holder, null);
                        } catch (IllegalArgumentException | IllegalAccessException ex) {
                            LOGGER.warn("Could not strip ModifiableVariable without Modification");
                        }
                    }
                }
            }
        }
        setExecuted(null);
    }

    @Override
    public List<Message> getSendMessages() {
        return messages;
    }

    @Override
    public List<BinaryPacket> getSendBinaryPackets() {
        return binaryPackets;
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
        final SendAction other = (SendAction) obj;
        if (!Objects.equals(this.messages, other.messages)) {
            return false;
        }
        if (!Objects.equals(this.binaryPackets, other.binaryPackets)) {
            return false;
        }
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 67 * hash + Objects.hashCode(this.messages);
        hash = 67 * hash + Objects.hashCode(this.binaryPackets);

        return hash;
    }

}
