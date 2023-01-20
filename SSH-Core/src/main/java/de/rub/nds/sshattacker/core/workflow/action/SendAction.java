/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.executor.MessageActionResult;
import jakarta.xml.bind.annotation.XmlElement;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * True if not all messages could be sent (due to an I/O error, for example).
     *
     * @see #isFailed
     * @see #setFailed
     */
    @XmlElement protected Boolean failed;

    public SendAction() {
        super();
    }

    public SendAction(List<ProtocolMessage<?>> messages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS, messages);
    }

    public SendAction(ProtocolMessage<?>... messages) {
        this(AliasedConnection.DEFAULT_CONNECTION_ALIAS, Arrays.asList(messages));
    }

    public SendAction(ProtocolMessage<?> message) {
        this(AliasedConnection.DEFAULT_CONNECTION_ALIAS, message);
    }

    public SendAction(String connectionAlias) {
        super(connectionAlias);
    }

    public SendAction(String connectionAlias, List<ProtocolMessage<?>> messages) {
        super(connectionAlias, messages);
    }

    public SendAction(String connectionAlias, ProtocolMessage<?>... messages) {
        super(connectionAlias, Arrays.asList(messages));
    }

    /**
     * Set the failure status of this action.
     *
     * @param failed {@code true} if the action has failed, else {@code false}
     * @see #isFailed
     */
    public void setFailed(final boolean failed) {
        this.failed = Boolean.valueOf(failed);
    }

    /**
     * Get the failure status of this action.
     *
     * @return {@code true} if the action has failed, else {@code false}
     * @see #setFailed
     */
    public boolean isFailed() {
        return Optional.ofNullable(this.failed).orElse(Boolean.FALSE).booleanValue();
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(connectionAlias);

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        String sending = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Sending messages: " + sending);
        } else {
            LOGGER.info("Sending messages (" + connectionAlias + "): " + sending);
        }

        messages.forEach(message -> message.getHandler(context).getPreparator().prepare());
        final MessageActionResult result =
                sendMessageHelper.sendMessages(context, messages.stream());

        // Check if all actions that were expected to be send were actually
        // sent or if some failure occurred.
        final int failedMessageCount = messages.size() - result.getPacketList().size();
        this.setFailed(failedMessageCount != 0);
        if (this.isFailed()) {
            LOGGER.error(
                    "Failed to send {} out of {} message(s)!", failedMessageCount, messages.size());
        }

        setExecuted(true);
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
            for (ProtocolMessage<?> message : messages) {
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
            for (ProtocolMessage<?> message : messages) {
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
        return this.isExecuted() && !this.isFailed();
    }

    @Override
    public void reset() {
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        if (messages != null) {
            for (ProtocolMessage<?> message : messages) {
                holders.addAll(message.getAllModifiableVariableHolders());
            }
        }
        for (ModifiableVariableHolder holder : holders) {
            List<Field> fields = holder.getAllModifiableVariableFields();
            for (Field f : fields) {
                f.setAccessible(true);

                ModifiableVariable<?> mv = null;
                try {
                    mv = (ModifiableVariable<?>) f.get(holder);
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
    public List<ProtocolMessage<?>> getSendMessages() {
        return messages;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        final SendAction that = (SendAction) o;
        return Objects.equals(this.messages, that.messages) && this.isFailed() == that.isFailed();
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), messages);
    }
}
