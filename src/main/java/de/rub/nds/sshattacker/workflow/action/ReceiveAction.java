/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.sshattacker.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.protocol.message.*;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.state.State;
import de.rub.nds.sshattacker.connection.AliasedConnection;
import de.rub.nds.sshattacker.workflow.action.result.MessageActionResult;
import java.util.*;
import javax.xml.bind.annotation.XmlElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    protected List<Message<?>> expectedMessages = new ArrayList<>();

    @XmlElement
    protected Boolean earlyCleanShutdown = null;

    @XmlElement
    protected Boolean checkOnlyExpected = null;

    public ReceiveAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public ReceiveAction(List<Message<?>> expectedMessages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.expectedMessages = expectedMessages;
    }

    public ReceiveAction(Message<?>... expectedMessages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.expectedMessages = new ArrayList<>(Arrays.asList(expectedMessages));
    }

    public ReceiveAction(Set<ReceiveOption> receiveOptions, List<Message<?>> messages) {
        this(messages);
        this.earlyCleanShutdown = receiveOptions.contains(ReceiveOption.EARLY_CLEAN_SHUTDOWN);
        this.checkOnlyExpected = receiveOptions.contains(ReceiveOption.CHECK_ONLY_EXPECTED);
    }

    public ReceiveAction(Set<ReceiveOption> receiveOptions, Message<?>... messages) {
        this(receiveOptions, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(ReceiveOption receiveOption, List<Message<?>> messages) {
        this(messages);
        switch (receiveOption) {
            case CHECK_ONLY_EXPECTED:
                this.checkOnlyExpected = true;
                break;
            case EARLY_CLEAN_SHUTDOWN:
                this.earlyCleanShutdown = true;
        }
    }

    public ReceiveAction(ReceiveOption receiveOption, Message<?>... messages) {
        this(receiveOption, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ReceiveAction(String connectionAliasAlias, List<Message<?>> messages) {
        super(connectionAliasAlias);
        this.expectedMessages = messages;
    }

    public ReceiveAction(String connectionAliasAlias, Message<?>... messages) {
        this(connectionAliasAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext sshContext = state.getSshContext(getConnectionAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving Messages...");
        MessageActionResult result = receiveMessageHelper.receiveMessages(expectedMessages, sshContext);
        binaryPackets = new ArrayList<>(result.getBinaryPacketList());
        messages = new ArrayList<>(result.getMessageList());
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
            for (Message<?> message : expectedMessages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n\tActual:");
        if ((messages != null) && (!messages.isEmpty())) {
            for (Message<?> message : messages) {
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
            for (Message<?> message : expectedMessages) {
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

    public List<Message<?>> getExpectedMessages() {
        return expectedMessages;
    }

    void setReceivedMessages(List<Message<?>> receivedMessages) {
        this.messages = receivedMessages;
    }

    void setReceivedRecords(List<BinaryPacket> receivedRecords) {
        this.binaryPackets = receivedRecords;
    }

    public void setExpectedMessages(List<Message<?>> expectedMessages) {
        this.expectedMessages = expectedMessages;
    }

    public void setExpectedMessages(Message<?>... expectedMessages) {
        this.expectedMessages = new ArrayList<>(Arrays.asList(expectedMessages));
    }

    @Override
    public void reset() {
        messages = null;
        binaryPackets = null;
        setExecuted(null);
    }

    @Override
    public List<Message<?>> getReceivedMessages() {
        return messages;
    }

    @Override
    public List<BinaryPacket> getReceivedBinaryPackets() {
        return binaryPackets;
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 67 * hash + Objects.hashCode(this.expectedMessages);
        hash = 67 * hash + Objects.hashCode(this.messages);
        hash = 67 * hash + Objects.hashCode(this.binaryPackets);

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
        final ReceiveAction other = (ReceiveAction) obj;
        if (!Objects.equals(this.expectedMessages, other.expectedMessages)) {
            return false;
        }
        if (!Objects.equals(this.messages, other.messages)) {
            return false;
        }
        if (!Objects.equals(this.binaryPackets, other.binaryPackets)) {
            return false;
        }
        return super.equals(obj);
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
