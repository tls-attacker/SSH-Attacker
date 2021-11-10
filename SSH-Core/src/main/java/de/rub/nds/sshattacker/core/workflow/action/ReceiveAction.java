/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.executor.MessageActionResult;
import java.util.*;
import javax.xml.bind.annotation.XmlElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    protected List<ProtocolMessage<?>> expectedMessages = new ArrayList<>();

    @XmlElement protected Boolean earlyCleanShutdown = null;

    @XmlElement protected Boolean checkOnlyExpected = null;

    public ReceiveAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public ReceiveAction(List<ProtocolMessage<?>> expectedMessages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.expectedMessages = expectedMessages;
    }

    public ReceiveAction(ProtocolMessage<?>... expectedMessages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.expectedMessages = new ArrayList<>(Arrays.asList(expectedMessages));
    }

    public ReceiveAction(Set<ReceiveOption> receiveOptions, List<ProtocolMessage<?>> messages) {
        this(messages);
        this.earlyCleanShutdown = receiveOptions.contains(ReceiveOption.EARLY_CLEAN_SHUTDOWN);
        this.checkOnlyExpected = receiveOptions.contains(ReceiveOption.CHECK_ONLY_EXPECTED);
    }

    public ReceiveAction(Set<ReceiveOption> receiveOptions, ProtocolMessage<?>... messages) {
        this(receiveOptions, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(ReceiveOption receiveOption, List<ProtocolMessage<?>> messages) {
        this(messages);
        switch (receiveOption) {
            case CHECK_ONLY_EXPECTED:
                this.checkOnlyExpected = true;
                break;
            case EARLY_CLEAN_SHUTDOWN:
                this.earlyCleanShutdown = true;
        }
    }

    public ReceiveAction(ReceiveOption receiveOption, ProtocolMessage<?>... messages) {
        this(receiveOption, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ReceiveAction(String connectionAliasAlias, List<ProtocolMessage<?>> messages) {
        super(connectionAliasAlias);
        this.expectedMessages = messages;
    }

    public ReceiveAction(String connectionAliasAlias, ProtocolMessage<?>... messages) {
        this(connectionAliasAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(getConnectionAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving Messages...");
        MessageActionResult result =
                receiveMessageHelper.receiveMessages(context, expectedMessages);
        setReceivedMessages(result.getMessageList());
        setExecuted(true);

        String expected = getReadableString(expectedMessages);
        LOGGER.debug("Receive Expected:" + expected);
        String received = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Received Messages: " + received);
        } else {
            LOGGER.info("Received Messages (" + getConnectionAlias() + "): " + received);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Receive Action:\n");

        sb.append("\tExpected:");
        if ((expectedMessages != null)) {
            for (ProtocolMessage<?> message : expectedMessages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n\tActual:");
        if ((messages != null) && (!messages.isEmpty())) {
            for (ProtocolMessage<?> message : messages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n");
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        if ((expectedMessages != null) && (!expectedMessages.isEmpty())) {
            sb.append(" (");
            for (ProtocolMessage<?> message : expectedMessages) {
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
        if (messages == null) {
            return false;
        }

        if (checkOnlyExpected != null && checkOnlyExpected) {
            if (expectedMessages.size() > messages.size()) {
                return false;
            }
        } else {
            if (messages.size() != expectedMessages.size()) {
                return false;
            }
        }
        for (int i = 0; i < expectedMessages.size(); i++) {
            if (!Objects.equals(expectedMessages.get(i).getClass(), messages.get(i).getClass())) {
                return false;
            }
        }

        return true;
    }

    public List<ProtocolMessage<?>> getExpectedMessages() {
        return expectedMessages;
    }

    void setReceivedMessages(List<ProtocolMessage<?>> receivedMessages) {
        this.messages = receivedMessages;
    }

    public void setExpectedMessages(List<ProtocolMessage<?>> expectedMessages) {
        this.expectedMessages = expectedMessages;
    }

    public void setExpectedMessages(ProtocolMessage<?>... expectedMessages) {
        this.expectedMessages = new ArrayList<>(Arrays.asList(expectedMessages));
    }

    @Override
    public void reset() {
        messages = null;
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage<?>> getReceivedMessages() {
        return messages;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ReceiveAction that = (ReceiveAction) o;
        return Objects.equals(expectedMessages, that.expectedMessages)
                && Objects.equals(messages, that.messages);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), expectedMessages, messages);
    }

    @Override
    public void normalize() {
        super.normalize();
        initEmptyLists();
    }

    @Override
    public void normalize(SshAction defaultAction) {
        super.normalize(defaultAction);
        initEmptyLists();
    }

    @Override
    public void filter() {
        super.filter();
        filterEmptyLists();
    }

    @Override
    public void filter(SshAction defaultCon) {
        super.filter(defaultCon);
        filterEmptyLists();
    }

    private void filterEmptyLists() {
        if (expectedMessages == null || expectedMessages.isEmpty()) {
            expectedMessages = null;
        }
    }

    private void initEmptyLists() {
        if (expectedMessages == null) {
            expectedMessages = new ArrayList<>();
        }
    }

    public enum ReceiveOption {
        EARLY_CLEAN_SHUTDOWN,
        CHECK_ONLY_EXPECTED;

        public static Set<ReceiveOption> bundle(ReceiveOption... receiveOptions) {
            return new HashSet<>(Arrays.asList(receiveOptions));
        }
    }
}
