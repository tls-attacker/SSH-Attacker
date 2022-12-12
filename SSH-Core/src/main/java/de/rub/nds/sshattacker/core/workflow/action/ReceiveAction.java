/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.executor.MessageActionResult;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            value = {
                // Authentication Protocol Messages
                @XmlElement(type = UserAuthBannerMessage.class, name = "UserAuthBanner"),
                @XmlElement(type = UserAuthFailureMessage.class, name = "UserAuthFailure"),
                @XmlElement(type = UserAuthHostbasedMessage.class, name = "UserAuthHostbased"),
                @XmlElement(type = UserAuthInfoRequestMessage.class, name = "UserAuthInfoRequest"),
                @XmlElement(
                        type = UserAuthInfoResponseMessage.class,
                        name = "UserAuthInfoResponse"),
                @XmlElement(
                        type = UserAuthKeyboardInteractiveMessage.class,
                        name = "UserAuthKeyboardInteractive"),
                @XmlElement(type = UserAuthNoneMessage.class, name = "UserAuthNone"),
                @XmlElement(type = UserAuthPasswordMessage.class, name = "UserAuthPassword"),
                @XmlElement(type = UserAuthPkOkMessage.class, name = "UserAuthPkOk"),
                @XmlElement(type = UserAuthPubkeyMessage.class, name = "UserAuthPubkey"),
                @XmlElement(type = UserAuthRequestMessage.class, name = "UserAuthRequest"),
                @XmlElement(type = UserAuthSuccessMessage.class, name = "UserAuthSuccess"),
                @XmlElement(type = UserAuthUnknownMessage.class, name = "UserAuthUnknownRequest"),
                // Connection Protocol Messages
                @XmlElement(type = ChannelCloseMessage.class, name = "ChannelClose"),
                @XmlElement(type = ChannelDataMessage.class, name = "ChannelData"),
                @XmlElement(type = ChannelEofMessage.class, name = "ChannelEof"),
                @XmlElement(type = ChannelExtendedDataMessage.class, name = "ChannelExtendedData"),
                @XmlElement(type = ChannelFailureMessage.class, name = "ChannelFailure"),
                @XmlElement(
                        type = ChannelOpenConfirmationMessage.class,
                        name = "ChannelOpenConfirmation"),
                @XmlElement(type = ChannelOpenFailureMessage.class, name = "ChannelOpenFailure"),
                @XmlElement(type = ChannelOpenMessage.class, name = "ChannelOpen"),
                @XmlElement(
                        type = ChannelRequestAuthAgentMessage.class,
                        name = "ChannelRequestAuthAgent"),
                @XmlElement(type = ChannelRequestBreakMessage.class, name = "ChannelRequestBreak"),
                @XmlElement(type = ChannelRequestEnvMessage.class, name = "ChannelRequestEnv"),
                @XmlElement(type = ChannelRequestExecMessage.class, name = "ChannelRequestExec"),
                @XmlElement(
                        type = ChannelRequestExitSignalMessage.class,
                        name = "ChannelRequestExitSignal"),
                @XmlElement(
                        type = ChannelRequestExitStatusMessage.class,
                        name = "ChannelRequestExitStatus"),
                @XmlElement(type = ChannelRequestPtyMessage.class, name = "ChannelRequestPty"),
                @XmlElement(type = ChannelRequestShellMessage.class, name = "ChannelRequestShell"),
                @XmlElement(
                        type = ChannelRequestSignalMessage.class,
                        name = "ChannelRequestSignal"),
                @XmlElement(
                        type = ChannelRequestSubsystemMessage.class,
                        name = "ChannelRequestSubsystem"),
                @XmlElement(
                        type = ChannelRequestUnknownMessage.class,
                        name = "ChannelRequestUnknown"),
                @XmlElement(
                        type = ChannelRequestWindowChangeMessage.class,
                        name = "ChannelRequestWindowChange"),
                @XmlElement(type = ChannelRequestX11Message.class, name = "ChannelRequestX11"),
                @XmlElement(
                        type = ChannelRequestXonXoffMessage.class,
                        name = "ChannelRequestXonXoff"),
                @XmlElement(type = ChannelSuccessMessage.class, name = "ChannelSuccess"),
                @XmlElement(type = ChannelWindowAdjustMessage.class, name = "ChannelWindowAdjust"),
                @XmlElement(
                        type = GlobalRequestCancelTcpIpForwardMessage.class,
                        name = "GlobalRequestCancelTcpIpForward"),
                @XmlElement(
                        type = GlobalRequestFailureMessage.class,
                        name = "GlobalRequestFailure"),
                @XmlElement(
                        type = GlobalRequestNoMoreSessionsMessage.class,
                        name = "GlobalRequestNoMoreSessions"),
                @XmlElement(
                        type = GlobalRequestSuccessMessage.class,
                        name = "GlobalRequestSuccess"),
                @XmlElement(
                        type = GlobalRequestTcpIpForwardMessage.class,
                        name = "GlobalRequestTcpIpForward"),
                @XmlElement(
                        type = GlobalRequestUnknownMessage.class,
                        name = "GlobalRequestUnknown"),
                // Transport Layer Protocol Messages
                @XmlElement(type = DebugMessage.class, name = "DebugMessage"),
                @XmlElement(
                        type = DhGexKeyExchangeGroupMessage.class,
                        name = "DhGexKeyExchangeGroup"),
                @XmlElement(
                        type = DhGexKeyExchangeInitMessage.class,
                        name = "DhGexKeyExchangeInit"),
                @XmlElement(
                        type = DhGexKeyExchangeOldRequestMessage.class,
                        name = "DhGexKeyExchangeOldRequest"),
                @XmlElement(
                        type = DhGexKeyExchangeReplyMessage.class,
                        name = "DhGexKeyExchangeReply"),
                @XmlElement(
                        type = DhGexKeyExchangeRequestMessage.class,
                        name = "DhGexKeyExchangeRequest"),
                @XmlElement(type = DhKeyExchangeInitMessage.class, name = "DhKeyExchangeInit"),
                @XmlElement(type = DhKeyExchangeReplyMessage.class, name = "DhKeyExchangeReply"),
                @XmlElement(type = DisconnectMessage.class, name = "DisconnectMessage"),
                @XmlElement(type = EcdhKeyExchangeInitMessage.class, name = "EcdhKeyExchangeInit"),
                @XmlElement(
                        type = EcdhKeyExchangeReplyMessage.class,
                        name = "EcdhKeyExchangeReply"),
                @XmlElement(type = IgnoreMessage.class, name = "IgnoreMessage"),
                @XmlElement(type = KeyExchangeInitMessage.class, name = "KeyExchangeInit"),
                @XmlElement(type = NewKeysMessage.class, name = "NewKeys"),
                @XmlElement(type = RsaKeyExchangeDoneMessage.class, name = "RsaKeyExchangeDone"),
                @XmlElement(
                        type = RsaKeyExchangePubkeyMessage.class,
                        name = "RsaKeyExchangePubkey"),
                @XmlElement(
                        type = RsaKeyExchangeSecretMessage.class,
                        name = "RsaKeyExchangeSecret"),
                @XmlElement(type = ServiceAcceptMessage.class, name = "ServiceAccept"),
                @XmlElement(type = ServiceRequestMessage.class, name = "ServiceRequest"),
                @XmlElement(type = UnimplementedMessage.class, name = "UnimplementedMessage"),
                @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
                @XmlElement(type = VersionExchangeMessage.class, name = "VersionExchange"),
                @XmlElement(type = AsciiMessage.class, name = "AsciiMessage")
            })
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

        LOGGER.debug("Receiving messages for connection alias '{}'...", getConnectionAlias());
        MessageActionResult result =
                receiveMessageHelper.receiveMessages(context, expectedMessages);
        setReceivedMessages(result.getMessageList());
        setExecuted(true);

        String expected = getReadableString(expectedMessages);
        LOGGER.debug("Expected messages: {}", expected);
        String received = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Received messages: {}", received);
        } else {
            LOGGER.info("Received messages ({}): {}", getConnectionAlias(), received);
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

        if (expectedMessages.size() == 0 && messages.size() > 0) {
            return true;
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
