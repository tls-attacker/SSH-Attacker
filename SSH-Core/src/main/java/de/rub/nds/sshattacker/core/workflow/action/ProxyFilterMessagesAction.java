/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestHostbasedMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPublicKeyHostboundOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPublicKeyMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestHostbasedMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestPublicKeyHostboundOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestPublicKeyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.sshattacker.core.workflow.action.executor.SendMessageHelper;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProxyFilterMessagesAction extends ForwardMessagesAction {

    private static final Logger LOGGER = LogManager.getLogger();

    // because sendMessages will contain filteredMessages, when storing the workflow trace, so it
    // would just make reading the trace more complicated
    @XmlTransient protected List<ProtocolMessage<?>> filteredMessages;

    public ProxyFilterMessagesAction() {
        super();
    }

    /* Allow to pass a fake ReceiveMessageHelper helper for testing. */
    protected ProxyFilterMessagesAction(String receiveFromAlias, String forwardToAlias) {
        super(receiveFromAlias, forwardToAlias);
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
        initLoggingSide(receiveFromCtx);

        receiveMessages(receiveFromCtx);
        handleReceivedMessages(receiveFromCtx);
        filterMessages(receiveFromCtx, forwardToCtx);
        forwardMessages(forwardToCtx);
        applyMessages(forwardToCtx);
    }

    @Override
    protected void forwardMessages(SshContext forwardToCtx) {
        LOGGER.info(
                "Forwarding messages ({}): {}",
                forwardToAlias,
                getReadableString(receivedMessages));
        MessageActionResult result =
                SendMessageHelper.sendMessages(forwardToCtx, filteredMessages.stream());
        sendMessages = result.getMessageList();

        if (executedAsPlanned) {
            executedAsPlanned = checkMessageListsEquals(sendMessages, messages);
        }
        setExecuted(true);
    }

    public void filterMessages(SshContext receiveFromCtx, SshContext forwardToCtx) {
        filteredMessages = receivedMessages;
        for (int i = 0; i < filteredMessages.size(); i++) {
            if (filteredMessages.get(i).getClass() == UserAuthRequestPublicKeyMessage.class) {
                filteredMessages.set(i, filterUserAuthRequestPublicKeyMessage(forwardToCtx));
            }
            if (filteredMessages.get(i).getClass() == UserAuthRequestHostbasedMessage.class) {
                filteredMessages.set(i, filterUserAuthRequestHostbasedMessage(forwardToCtx));
            }
            if (filteredMessages.get(i).getClass()
                    == UserAuthRequestPublicKeyHostboundOpenSshMessage.class) {
                filteredMessages.set(
                        i, filterUserAuthRequestPublicKeyHostboundOpenSshMessage(forwardToCtx));
            }
        }
    }

    public static UserAuthRequestPublicKeyMessage filterUserAuthRequestPublicKeyMessage(
            SshContext forwardToCtx) {
        UserAuthRequestPublicKeyMessage newMessage = new UserAuthRequestPublicKeyMessage();
        UserAuthRequestPublicKeyMessagePreparator forwardContextPreparator =
                new UserAuthRequestPublicKeyMessagePreparator(
                        forwardToCtx.getChooser(), newMessage);
        forwardContextPreparator.prepare();
        return newMessage;
    }

    public static UserAuthRequestHostbasedMessage filterUserAuthRequestHostbasedMessage(
            SshContext forwardToCtx) {
        UserAuthRequestHostbasedMessage newMessage = new UserAuthRequestHostbasedMessage();
        UserAuthRequestHostbasedMessagePreparator forwardContextPreparator =
                new UserAuthRequestHostbasedMessagePreparator(
                        forwardToCtx.getChooser(), newMessage);
        forwardContextPreparator.prepare();
        return newMessage;
    }

    public static UserAuthRequestPublicKeyHostboundOpenSshMessage
            filterUserAuthRequestPublicKeyHostboundOpenSshMessage(SshContext forwardToCtx) {
        UserAuthRequestPublicKeyHostboundOpenSshMessage newMessage =
                new UserAuthRequestPublicKeyHostboundOpenSshMessage();
        UserAuthRequestPublicKeyHostboundOpenSshMessagePreparator forwardContextPreparator =
                new UserAuthRequestPublicKeyHostboundOpenSshMessagePreparator(
                        forwardToCtx.getChooser(), newMessage);
        forwardContextPreparator.prepare();
        return newMessage;
    }
}
