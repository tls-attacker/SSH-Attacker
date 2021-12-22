/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import java.lang.reflect.Field;
import java.util.*;
import javax.xml.bind.annotation.XmlAttribute;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlAttribute(name = "channel")
    protected Integer senderChannel = null;

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

    public SendAction(Integer senderChannel) {
        super();
        this.senderChannel = senderChannel;
    }

    public SendAction(List<ProtocolMessage<?>> messages, Integer senderChannel) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS, messages);
        this.senderChannel = senderChannel;
    }

    public SendAction(Integer senderChannel, ProtocolMessage<?>... messages) {
        this(AliasedConnection.DEFAULT_CONNECTION_ALIAS, Arrays.asList(messages));
        this.senderChannel = senderChannel;
    }

    public SendAction(ProtocolMessage<?> message, Integer senderChannel) {
        this(AliasedConnection.DEFAULT_CONNECTION_ALIAS, message);
    }

    public SendAction(String connectionAlias, Integer senderChannel) {
        super(connectionAlias);
        this.senderChannel = senderChannel;
    }

    public SendAction(
            String connectionAlias, List<ProtocolMessage<?>> messages, Integer senderChannel) {
        super(connectionAlias, messages);
        this.senderChannel = senderChannel;
    }

    public SendAction(
            String connectionAlias, Integer senderChannel, ProtocolMessage<?>... messages) {
        super(connectionAlias, Arrays.asList(messages));
        this.senderChannel = senderChannel;
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

        for (ProtocolMessage<?> message : messages) {
            if (senderChannel != null) {
                if (ChannelMessage.class.isInstance(message)
                        || message.getClass() == ChannelOpenMessage.class) {
                    message.getHandler(context).getChannelPreparator(senderChannel).prepare();
                } else {
                    LOGGER.warn("No channel support given on this message layer!");
                    message.getHandler(context).getPreparator().prepare();
                }
            } else {
                message.getHandler(context).getPreparator().prepare();
            }
        }
        sendMessageHelper.sendMessages(context, messages.stream());
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
        return isExecuted();
    }

    @Override
    public void reset() {
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        if (messages != null) {
            Config config = new Config();
            List<Class> skipResetClasses = config.getSkipResetClasses();

            for (ProtocolMessage<?> message : messages) {
                if (!skipResetClasses.contains(message.getClass())) {
                    holders.addAll(message.getAllModifiableVariableHolders());
                }
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
        SendAction that = (SendAction) o;
        return Objects.equals(messages, that.messages);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), messages);
    }
}
