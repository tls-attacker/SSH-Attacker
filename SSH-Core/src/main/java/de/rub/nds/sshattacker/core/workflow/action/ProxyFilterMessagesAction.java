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
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.sshattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.sshattacker.core.workflow.action.executor.SendMessageHelper;
import java.util.List;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementWrapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProxyFilterMessagesAction extends ForwardMessagesAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElementWrapper @HoldsModifiableVariable @XmlElementRef
    protected List<ProtocolMessage<?>> filteredMessages;

    public ProxyFilterMessagesAction() {
        this.receiveMessageHelper = new ReceiveMessageHelper();
        this.sendMessageHelper = new SendMessageHelper();
    }

    public ProxyFilterMessagesAction(String receiveFromAlias, String forwardToAlias) {
        super(receiveFromAlias, forwardToAlias, new ReceiveMessageHelper());
    }

    /** Allow to pass a fake ReceiveMessageHelper helper for testing. */
    protected ProxyFilterMessagesAction(
            String receiveFromAlias,
            String forwardToAlias,
            ReceiveMessageHelper receiveMessageHelper) {
        super(receiveFromAlias, forwardToAlias, receiveMessageHelper);
    }

    public ProxyFilterMessagesAction(
            String receiveFromAlias, String forwardToAlias, List<ProtocolMessage<?>> messages) {
        super(receiveFromAlias, forwardToAlias, messages);
    }

    public ProxyFilterMessagesAction(
            String receiveFromAlias, String forwardToAlias, ProtocolMessage<?>... messages) {
        super(receiveFromAlias, forwardToAlias, messages);
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
        handleReceivedMessages(receiveFromCtx);
        filterMessages(receiveFromCtx);
        forwardMessages(forwardToCtx);
        applyMessages(forwardToCtx);
    }

    @Override
    protected void forwardMessages(SshContext forwardToCtx) {
        LOGGER.info(
                "Forwarding messages ("
                        + forwardToAlias
                        + "): "
                        + getReadableString(receivedMessages));
        MessageActionResult result =
                sendMessageHelper.sendMessages(forwardToCtx, filteredMessages.stream());
        sendMessages = result.getMessageList();

        if (executedAsPlanned) {
            executedAsPlanned = checkMessageListsEquals(sendMessages, messages);
        }
        setExecuted(true);
    }

    public void filterMessages(SshContext receiveFromCtx) {
        filteredMessages = receivedMessages;
    }
}
