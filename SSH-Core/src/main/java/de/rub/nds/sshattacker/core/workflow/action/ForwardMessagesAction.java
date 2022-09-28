/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.packet.layer.AbstractPacketLayer;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.sshattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ForwardMessagesAction extends SshAction implements ReceivingAction, SendingAction {
    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "from")
    protected String receiveFromAlias = null;

    @XmlElement(name = "to")
    protected String forwardToAlias = null;

    @XmlTransient protected Boolean executedAsPlanned = null;

    /** If you want true here, use the more verbose ForwardMessagesWithPrepareAction. */
    @XmlTransient protected Boolean withPrepare = false;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage<?>> receivedMessages;

    @XmlElementWrapper @HoldsModifiableVariable @XmlElementRef
    protected List<ProtocolMessage<?>> messages;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage<?>> sendMessages;

    @XmlTransient protected ReceiveMessageHelper receiveMessageHelper;

    @XmlTransient protected SendMessageHelper sendMessageHelper;

    private byte[] receivedBytes;

    public ForwardMessagesAction() {
        this.receiveMessageHelper = new ReceiveMessageHelper();
        this.sendMessageHelper = new SendMessageHelper();
    }

    public ForwardMessagesAction(String receiveFromAlias, String forwardToAlias) {
        this(receiveFromAlias, forwardToAlias, new ReceiveMessageHelper());
    }

    /** Allow to pass a fake ReceiveMessageHelper helper for testing. */
    protected ForwardMessagesAction(
            String receiveFromAlias,
            String forwardToAlias,
            ReceiveMessageHelper receiveMessageHelper) {
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
        this.receiveMessageHelper = receiveMessageHelper;
        this.sendMessageHelper = new SendMessageHelper();
    }

    public ForwardMessagesAction(
            String receiveFromAlias, String forwardToAlias, List<ProtocolMessage<?>> messages) {
        this.messages = messages;
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
        this.receiveMessageHelper = new ReceiveMessageHelper();
        this.sendMessageHelper = new SendMessageHelper();
    }

    public ForwardMessagesAction(
            String receiveFromAlias, String forwardToAlias, ProtocolMessage<?>... messages) {
        this(receiveFromAlias, forwardToAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    public void setReceiveFromAlias(String receiveFromAlias) {
        this.receiveFromAlias = receiveFromAlias;
    }

    public void setForwardToAlias(String forwardToAlias) {
        this.forwardToAlias = forwardToAlias;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        assertAliasesSetProperly();

        SshContext receiveFromCtx = state.getSshContext(receiveFromAlias);
        SshContext forwardToCtx = state.getSshContext(forwardToAlias);

        receiveMessages(receiveFromCtx);
        forwardMessages(forwardToCtx);
        handleReceivedMessages(receiveFromCtx);
        applyMessages(forwardToCtx);
    }

    protected void receiveMessages(SshContext receiveFromCtx) {
        LOGGER.debug("Receiving Messages...");
        try {
            receivedBytes = receiveMessageHelper.receiveBytes(receiveFromCtx);
        } catch (IOException e) {
            LOGGER.warn(
                    "Received an IOException while fetching data from socket: {}",
                    e.getLocalizedMessage());
            LOGGER.debug(e);
            receiveFromCtx.setReceivedTransportHandlerException(true);
        }
    }

    protected void forwardMessages(SshContext forwardToCtx) {
        LOGGER.info(
                "Forwarding messages ("
                        + forwardToAlias
                        + "): "
                        + getReadableString(receivedMessages));
        try {
            AbstractPacketLayer packetLayer = forwardToCtx.getPacketLayer();
            TransportHandler transportHandler = forwardToCtx.getTransportHandler();
            transportHandler.sendData(receivedBytes);
            if (messages.get(0).getClass() != VersionExchangeMessage.class) {
                forwardToCtx.incrementWriteSequenceNumber();
            }
            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            executedAsPlanned = false;
            setExecuted(false);
        }
    }

    protected void handleReceivedMessages(SshContext ctx) {
        receivedMessages =
                receiveMessageHelper.handleReceivedBytes(ctx, receivedBytes).getMessageList();
        String expected = getReadableString(messages);
        LOGGER.debug("Receive Expected (" + receiveFromAlias + "): " + expected);
        String received = getReadableString(receivedMessages);
        LOGGER.info("Received Messages (" + receiveFromAlias + "): " + received);

        executedAsPlanned = checkMessageListsEquals(messages, receivedMessages);
    }
    /**
     * Apply the contents of the messages to the given TLS context.
     *
     * @param ctx SSH context
     */
    protected void applyMessages(SshContext ctx) {
        changeSshContextHandling(ctx);
        for (ProtocolMessage<?> msg : receivedMessages) {
            LOGGER.debug("Applying " + msg.toCompactString() + " to forward context " + ctx);
            ProtocolMessageHandler<?> h = msg.getHandler(ctx);
            h.adjustContext();
        }
        changeSshContextHandling(ctx);
    }

    private void changeSshContextHandling(SshContext ctx) {
        ctx.setHandleAsClient(!ctx.isHandleAsClient());
    }

    public String getReceiveFromAlias() {
        return receiveFromAlias;
    }

    public String getForwardToAlias() {
        return forwardToAlias;
    }

    // TODO: yes, the correct way would be implement equals() for all
    // ProtocolMessages...
    protected boolean checkMessageListsEquals(
            List<ProtocolMessage<?>> expectedMessages, List<ProtocolMessage<?>> actualMessages) {
        boolean actualEmpty = true;
        boolean expectedEmpty = true;
        if (actualMessages != null && !actualMessages.isEmpty()) {
            actualEmpty = false;
        }
        if (expectedMessages != null && !expectedMessages.isEmpty()) {
            expectedEmpty = false;
        }
        if (actualEmpty && expectedEmpty) {
            return true;
        }
        if (actualEmpty != expectedEmpty) {
            return false;
        }
        if (actualMessages.size() != expectedMessages.size()) {
            return false;
        } else {
            for (int i = 0; i < actualMessages.size(); i++) {
                if (!actualMessages.get(i).getClass().equals(expectedMessages.get(i).getClass())) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public boolean executedAsPlanned() {
        return executedAsPlanned;
    }

    @Override
    public void reset() {
        receivedMessages = null;
        sendMessages = null;
        executedAsPlanned = false;
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage<?>> getReceivedMessages() {
        return receivedMessages;
    }

    @Override
    public List<ProtocolMessage<?>> getSendMessages() {
        return sendMessages;
    }

    public List<ProtocolMessage<?>> getMessages() {
        return messages;
    }

    public void setMessages(List<ProtocolMessage<?>> messages) {
        this.messages = messages;
    }

    public void setMessages(ProtocolMessage<?>... messages) {
        this.messages = new ArrayList<>(Arrays.asList(messages));
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + Objects.hashCode(this.receiveFromAlias);
        hash = 89 * hash + Objects.hashCode(this.forwardToAlias);
        hash = 89 * hash + Objects.hashCode(this.executedAsPlanned);
        hash = 89 * hash + Objects.hashCode(this.receivedMessages);
        hash = 89 * hash + Objects.hashCode(this.sendMessages);
        hash = 89 * hash + Objects.hashCode(this.messages);
        return hash;
    }

    /**
     * TODO: the equals methods for message/record actions and similar classes would require that
     * messages and records implement equals for a proper implementation. The present approach is
     * not satisfying.
     */
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
        final ForwardMessagesAction other = (ForwardMessagesAction) obj;
        if (!Objects.equals(this.receiveFromAlias, other.receiveFromAlias)) {
            return false;
        }
        if (!Objects.equals(this.forwardToAlias, other.forwardToAlias)) {
            return false;
        }
        if (!Objects.equals(this.executedAsPlanned, other.executedAsPlanned)) {
            return false;
        }
        if (!checkMessageListsEquals(this.receivedMessages, other.receivedMessages)) {
            return false;
        }
        if (!checkMessageListsEquals(this.sendMessages, other.sendMessages)) {
            return false;
        }
        return Objects.equals(this.messages, other.messages);
    }

    @Override
    public Set<String> getAllAliases() {
        Set<String> aliases = new LinkedHashSet<>();
        aliases.add(forwardToAlias);
        aliases.add(receiveFromAlias);
        return aliases;
    }

    @Override
    public void assertAliasesSetProperly() throws WorkflowExecutionException {
        if ((receiveFromAlias == null) || (receiveFromAlias.isEmpty())) {
            throw new WorkflowExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty receive alias (if using XML: add <from/>)");
        }
        if ((forwardToAlias == null) || (forwardToAlias.isEmpty())) {
            throw new WorkflowExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty forward alis (if using XML: add <to/>)");
        }
    }

    public String getReadableString(List<ProtocolMessage<?>> messages) {
        return getReadableString(messages, false);
    }

    public String getReadableString(List<ProtocolMessage<?>> messages, Boolean verbose) {
        StringBuilder builder = new StringBuilder();
        if (messages == null) {
            return builder.toString();
        }
        for (ProtocolMessage<?> message : messages) {
            if (verbose) {
                builder.append(message.toString());
            } else {
                builder.append(message.toCompactString());
            }
            if (!message.isRequired()) {
                builder.append("*");
            }
            builder.append(", ");
        }
        return builder.toString();
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
        stripEmptyLists();
    }

    @Override
    public void filter(SshAction defaultAction) {
        super.filter(defaultAction);
        stripEmptyLists();
    }

    private void stripEmptyLists() {
        if (messages == null || messages.isEmpty()) {
            messages = null;
        }
        if (receivedMessages == null || receivedMessages.isEmpty()) {
            receivedMessages = null;
        }

        if (sendMessages == null || sendMessages.isEmpty()) {
            sendMessages = null;
        }
    }

    private void initEmptyLists() {
        if (messages == null) {
            messages = new ArrayList<>();
        }
        if (receivedMessages == null) {
            receivedMessages = new ArrayList<>();
        }
        if (sendMessages == null) {
            sendMessages = new ArrayList<>();
        }
    }
}
