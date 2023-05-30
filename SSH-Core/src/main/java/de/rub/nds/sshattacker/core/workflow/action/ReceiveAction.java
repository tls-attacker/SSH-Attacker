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
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.sshattacker.core.workflow.action.executor.ReceiveMessageHelper;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.*;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements({
        // Authentication Protocol Messages
        @XmlElement(type = UserAuthBannerMessage.class, name = "UserAuthBanner"),
        @XmlElement(type = UserAuthFailureMessage.class, name = "UserAuthFailure"),
        @XmlElement(type = UserAuthHostbasedMessage.class, name = "UserAuthHostbased"),
        @XmlElement(type = UserAuthInfoRequestMessage.class, name = "UserAuthInfoRequest"),
        @XmlElement(type = UserAuthInfoResponseMessage.class, name = "UserAuthInfoResponse"),
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
        @XmlElement(type = ChannelOpenConfirmationMessage.class, name = "ChannelOpenConfirmation"),
        @XmlElement(type = ChannelOpenFailureMessage.class, name = "ChannelOpenFailure"),
        @XmlElement(type = ChannelOpenSessionMessage.class, name = "ChannelOpenSession"),
        @XmlElement(type = ChannelOpenUnknownMessage.class, name = "ChannelOpenUnknown"),
        @XmlElement(type = ChannelRequestAuthAgentMessage.class, name = "ChannelRequestAuthAgent"),
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
        @XmlElement(type = ChannelRequestSignalMessage.class, name = "ChannelRequestSignal"),
        @XmlElement(type = ChannelRequestSubsystemMessage.class, name = "ChannelRequestSubsystem"),
        @XmlElement(type = ChannelRequestUnknownMessage.class, name = "ChannelRequestUnknown"),
        @XmlElement(
                type = ChannelRequestWindowChangeMessage.class,
                name = "ChannelRequestWindowChange"),
        @XmlElement(type = ChannelRequestX11Message.class, name = "ChannelRequestX11"),
        @XmlElement(type = ChannelRequestXonXoffMessage.class, name = "ChannelRequestXonXoff"),
        @XmlElement(type = ChannelSuccessMessage.class, name = "ChannelSuccess"),
        @XmlElement(type = ChannelWindowAdjustMessage.class, name = "ChannelWindowAdjust"),
        @XmlElement(
                type = GlobalRequestCancelTcpIpForwardMessage.class,
                name = "GlobalRequestCancelTcpIpForward"),
        @XmlElement(type = GlobalRequestFailureMessage.class, name = "GlobalRequestFailure"),
        @XmlElement(
                type = GlobalRequestNoMoreSessionsMessage.class,
                name = "GlobalRequestNoMoreSessions"),
        @XmlElement(type = GlobalRequestSuccessMessage.class, name = "GlobalRequestSuccess"),
        @XmlElement(
                type = GlobalRequestTcpIpForwardMessage.class,
                name = "GlobalRequestTcpIpForward"),
        @XmlElement(
                type = GlobalRequestOpenSshHostKeysMessage.class,
                name = "GlobalRequestOpenSshHostKeys"),
        @XmlElement(type = GlobalRequestUnknownMessage.class, name = "GlobalRequestUnknown"),
        // Transport Layer Protocol Messages
        @XmlElement(type = DebugMessage.class, name = "DebugMessage"),
        @XmlElement(type = DhGexKeyExchangeGroupMessage.class, name = "DhGexKeyExchangeGroup"),
        @XmlElement(type = DhGexKeyExchangeInitMessage.class, name = "DhGexKeyExchangeInit"),
        @XmlElement(
                type = DhGexKeyExchangeOldRequestMessage.class,
                name = "DhGexKeyExchangeOldRequest"),
        @XmlElement(type = DhGexKeyExchangeReplyMessage.class, name = "DhGexKeyExchangeReply"),
        @XmlElement(type = DhGexKeyExchangeRequestMessage.class, name = "DhGexKeyExchangeRequest"),
        @XmlElement(type = DhKeyExchangeInitMessage.class, name = "DhKeyExchangeInit"),
        @XmlElement(type = DhKeyExchangeReplyMessage.class, name = "DhKeyExchangeReply"),
        @XmlElement(type = DisconnectMessage.class, name = "DisconnectMessage"),
        @XmlElement(type = EcdhKeyExchangeInitMessage.class, name = "EcdhKeyExchangeInit"),
        @XmlElement(type = EcdhKeyExchangeReplyMessage.class, name = "EcdhKeyExchangeReply"),
        @XmlElement(type = ExtensionInfoMessage.class, name = "ExtensionInfo"),
        @XmlElement(type = IgnoreMessage.class, name = "IgnoreMessage"),
        @XmlElement(type = KeyExchangeInitMessage.class, name = "KeyExchangeInit"),
        @XmlElement(type = NewCompressMessage.class, name = "NewCompress"),
        @XmlElement(type = NewKeysMessage.class, name = "NewKeys"),
        @XmlElement(type = RsaKeyExchangeDoneMessage.class, name = "RsaKeyExchangeDone"),
        @XmlElement(type = RsaKeyExchangePubkeyMessage.class, name = "RsaKeyExchangePubkey"),
        @XmlElement(type = RsaKeyExchangeSecretMessage.class, name = "RsaKeyExchangeSecret"),
        @XmlElement(type = ServiceAcceptMessage.class, name = "ServiceAccept"),
        @XmlElement(type = ServiceRequestMessage.class, name = "ServiceRequest"),
        @XmlElement(type = UnimplementedMessage.class, name = "UnimplementedMessage"),
        @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
        @XmlElement(type = VersionExchangeMessage.class, name = "VersionExchange"),
        @XmlElement(type = AsciiMessage.class, name = "AsciiMessage"),
        @XmlElement(type = HybridKeyExchangeInitMessage.class, name = "HybridKeyExchangeInit"),
        @XmlElement(type = HybridKeyExchangeReplyMessage.class, name = "HybridKeyExchangeReply")
    })
    protected List<ProtocolMessage<?>> expectedMessages = new ArrayList<>();

    /**
     * Set to {@code true} if the {@link ReceiveOption#EARLY_CLEAN_SHUTDOWN} option has been set.
     */
    @XmlElement protected Boolean earlyCleanShutdown;

    /** Set to {@code true} if the {@link ReceiveOption#CHECK_ONLY_EXPECTED} option has been set. */
    @XmlElement protected Boolean checkOnlyExpected;

    /**
     * Set to {@code true} if the {@link
     * ReceiveOption#IGNORE_UNEXPECTED_GLOBAL_REQUESTS_WITHOUT_WANTREPLY} option has been set.
     */
    @XmlElement protected Boolean ignoreUnexpectedGlobalRequestsWithoutWantReply;

    /**
     * Set to {@code true} if the {@link ReceiveOption#FAIL_ON_UNEXPECTED_IGNORE_MESSAGES} option
     * has been set.
     */
    @XmlElement protected Boolean failOnUnexpectedIgnoreMessages;

    /**
     * Set to {@code true} if the {@link ReceiveOption#FAIL_ON_UNEXPECTED_DEBUG_MESSAGES} option has
     * been set.
     */
    @XmlElement protected Boolean failOnUnexpectedDebugMessages;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements({
        @XmlElement(type = BlobPacket.class, name = "BlobPacket"),
        @XmlElement(type = BinaryPacket.class, name = "BinaryPacket")
    })
    protected List<AbstractPacket> packetList = new ArrayList<>();

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

    public ReceiveAction(
            Set<ReceiveOption> receiveOptions, List<ProtocolMessage<?>> expectedMessages) {
        this(expectedMessages);
        setReceiveOptions(receiveOptions);
    }

    public ReceiveAction(Set<ReceiveOption> receiveOptions, ProtocolMessage<?>... messages) {
        this(receiveOptions, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(ReceiveOption receiveOption, List<ProtocolMessage<?>> expectedMessages) {
        this(Set.of(receiveOption), expectedMessages);
    }

    public ReceiveAction(ReceiveOption receiveOption, ProtocolMessage<?>... messages) {
        this(receiveOption, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ReceiveAction(String connectionAlias, List<ProtocolMessage<?>> messages) {
        super(connectionAlias);
        expectedMessages = messages;
    }

    public ReceiveAction(String connectionAlias, ProtocolMessage<?>... messages) {
        this(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(getConnectionAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving messages for connection alias '{}'...", getConnectionAlias());
        MessageActionResult result =
                ReceiveMessageHelper.receiveMessages(context, expectedMessages);
        messages = result.getMessageList();
        packetList = result.getPacketList();
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
        if (expectedMessages != null) {
            for (ProtocolMessage<?> message : expectedMessages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n\tActual:");
        if (messages != null && !messages.isEmpty()) {
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
        if (expectedMessages != null && !expectedMessages.isEmpty()) {
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

        // If no expected messages were defined, we consider this receive
        // action as "let's see what the other side sends".
        if (expectedMessages.isEmpty()) {
            // FIXME: In case TLS-Attacker's `GenericReceiveAction` is ported
            // to SSH-Attacker at some point and the `messages` list is also
            // empty, it might make sense to log a warning that tells the user
            // to use the `GenericReceiveAction` instead. If you truly don't
            // know what the other side will send, it makes sense to wait the
            // full timeout for incoming data (not exit early after the first
            // chunk of data has been received).
            return true;
        }

        // This action expected more messages than it received. This means we
        // can fail early.
        if (expectedMessages.size() > messages.size()) {
            return false;
        }

        Iterator<ProtocolMessage<?>> actualMessages = messages.iterator();
        for (ProtocolMessage<?> expectedMessage : expectedMessages) {
            while (true) {
                if (!actualMessages.hasNext()) {
                    // There is still at least one expected message left that
                    // didn't match any received messages. This action did not
                    // execute as expected.
                    LOGGER.debug(
                            "Expected message of type {} has not been received!",
                            expectedMessage.toCompactString());
                    return false;
                }

                ProtocolMessage<?> actualMessage = actualMessages.next();

                // Check if the actual message matches the expected message. If
                // so, continue with the next expected message.
                if (Objects.equals(expectedMessage.getClass(), actualMessage.getClass())) {
                    break;
                }

                // This action received an unexpected message. This means that
                // this action has not been executed as planned, unless:
                //
                // - the `CHECK_ONLY_EXPECTED` receive option is set, or
                // - the `IGNORE_UNEXPECTED_GLOBAL_REQUESTS_WITHOUT_WANTREPLY`
                //   receive option is set and the actual message is an
                //   SSH_MSG_GLOBAL_REQUEST where the `want_reply` field is set
                //   to 0.
                // - the `FAIL_ON_UNEXPECTED_IGNORE_MESSAGES` receive option is not
                //   set and the actual message is an SSH_MSG_IGNORE message.
                //
                // In these cases, ignore the received message and check if the
                // next received message matches the expected message.
                if (hasReceiveOption(ReceiveOption.CHECK_ONLY_EXPECTED)
                        || hasReceiveOption(
                                        ReceiveOption
                                                .IGNORE_UNEXPECTED_GLOBAL_REQUESTS_WITHOUT_WANTREPLY)
                                && actualMessage instanceof GlobalRequestMessage
                                && ((GlobalRequestMessage<?>) actualMessage)
                                                .getWantReply()
                                                .getValue()
                                        == 0
                        || !hasReceiveOption(ReceiveOption.FAIL_ON_UNEXPECTED_IGNORE_MESSAGES)
                                && actualMessage instanceof IgnoreMessage
                        || !hasReceiveOption(ReceiveOption.FAIL_ON_UNEXPECTED_DEBUG_MESSAGES)
                                && actualMessage instanceof DebugMessage) {
                    LOGGER.debug("Ignoring message of type {}.", actualMessage.toCompactString());
                    continue;
                }

                // At this point, we received a message that was unexpected and
                // that we cannot ignore.
                LOGGER.debug(
                        "Received unexpected message of type {}.", actualMessage.toCompactString());
                return false;
            }
        }

        // At this point, all expected messages have been received. If
        // `MessageHelper::receiveMessages` behaves correctly, then the
        // `actualMessages` iterator should be empty at this point (because the
        // method should stop receiving after the last expected message).
        //
        // If this assumption is violated and the iterator still contains
        // messages, then that is a bug and this method may not work correctly.
        assert !actualMessages.hasNext()
                : "MessageHelper::receiveMessages did not stop receiving after the last expected message";

        return true;
    }

    public List<ProtocolMessage<?>> getExpectedMessages() {
        return expectedMessages;
    }

    @SuppressWarnings("SuspiciousGetterSetter")
    void setReceivedMessages(List<ProtocolMessage<?>> receivedMessages) {
        messages = receivedMessages;
    }

    public List<AbstractPacket> getPacketList() {
        return packetList;
    }

    public void setPacketList(List<AbstractPacket> packetList) {
        this.packetList = packetList;
    }

    public void setExpectedMessages(List<ProtocolMessage<?>> expectedMessages) {
        this.expectedMessages = expectedMessages;
    }

    public void setExpectedMessages(ProtocolMessage<?>... expectedMessages) {
        this.expectedMessages = new ArrayList<>(Arrays.asList(expectedMessages));
    }

    /**
     * Check if the reception option is set.
     *
     * @param option a receive option
     * @return {@code true} if the reception option is set, else {@code false}
     */
    protected boolean hasReceiveOption(ReceiveOption option) {
        Boolean value = null;
        switch (option) {
            case EARLY_CLEAN_SHUTDOWN:
                value = earlyCleanShutdown;
                break;
            case CHECK_ONLY_EXPECTED:
                value = checkOnlyExpected;
                break;
            case IGNORE_UNEXPECTED_GLOBAL_REQUESTS_WITHOUT_WANTREPLY:
                value = ignoreUnexpectedGlobalRequestsWithoutWantReply;
                break;
            case FAIL_ON_UNEXPECTED_IGNORE_MESSAGES:
                value = failOnUnexpectedIgnoreMessages;
                break;
            case FAIL_ON_UNEXPECTED_DEBUG_MESSAGES:
                value = failOnUnexpectedDebugMessages;
                break;
        }

        return value != null && value;
    }

    /**
     * Get the reception options for this action.
     *
     * @return set of receive options
     */
    public Set<ReceiveOption> getReceiveOptions() {
        return Arrays.stream(ReceiveOption.values())
                .filter(this::hasReceiveOption)
                .collect(Collectors.toSet());
    }

    /**
     * Set the reception options for this action.
     *
     * @param receiveOptions set of receive options
     */
    public void setReceiveOptions(Set<ReceiveOption> receiveOptions) {
        earlyCleanShutdown = receiveOptions.contains(ReceiveOption.EARLY_CLEAN_SHUTDOWN);
        checkOnlyExpected = receiveOptions.contains(ReceiveOption.CHECK_ONLY_EXPECTED);
        ignoreUnexpectedGlobalRequestsWithoutWantReply =
                receiveOptions.contains(
                        ReceiveOption.IGNORE_UNEXPECTED_GLOBAL_REQUESTS_WITHOUT_WANTREPLY);
        failOnUnexpectedIgnoreMessages =
                receiveOptions.contains(ReceiveOption.FAIL_ON_UNEXPECTED_IGNORE_MESSAGES);
        failOnUnexpectedDebugMessages =
                receiveOptions.contains(ReceiveOption.FAIL_ON_UNEXPECTED_DEBUG_MESSAGES);

        if (hasReceiveOption(ReceiveOption.CHECK_ONLY_EXPECTED)
                && hasReceiveOption(ReceiveOption.FAIL_ON_UNEXPECTED_IGNORE_MESSAGES)) {
            LOGGER.warn(
                    "ReceiveAction has conflicting options CHECK_ONLY_EXPECTED and FAIL_ON_UNEXPECTED_IGNORE_MESSAGES set, the latter will have no effect.");
        }
    }

    @Override
    public void reset() {
        messages = null;
        setExecuted(null);
    }

    @SuppressWarnings("SuspiciousGetterSetter")
    @Override
    public List<ProtocolMessage<?>> getReceivedMessages() {
        return messages;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        if (!super.equals(obj)) return false;
        ReceiveAction that = (ReceiveAction) obj;
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
    public void filter(SshAction defaultAction) {
        super.filter(defaultAction);
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
        /**
         * Ignore additional messages of any type when checking if the reception action was executed
         * as planned.
         *
         * <p>If both this option and {@link ReceiveOption#FAIL_ON_UNEXPECTED_IGNORE_MESSAGES} have
         * been set, this option takes precedence and ignore messages will still be ignored.
         */
        CHECK_ONLY_EXPECTED,
        /**
         * Ignore unexpected {@code SSH_MSG_GLOBAL_REQUEST} messages where {@code want_reply} is set
         * to {@code 0} when checking if the reception action was executed as planned.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-4">RFC 4254, section
         *     4 "Global Requests"</a>
         */
        IGNORE_UNEXPECTED_GLOBAL_REQUESTS_WITHOUT_WANTREPLY,
        /**
         * Do not ignore unexpected {@code SSH_MSG_IGNORE} messages when checking if the reception
         * action was executed as planned. Instead, such messages will cause {@link
         * #executedAsPlanned} to return {@code false}.
         *
         * <p>If both this option and {@link ReceiveOption#CHECK_ONLY_EXPECTED} have been set, the
         * latter takes precedence and {@code SSH_MSG_IGNORE} messages will still be ignored.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-11.2">RFC 4253,
         *     section 11.2 "Ignored Data Message"</a>
         */
        FAIL_ON_UNEXPECTED_IGNORE_MESSAGES,
        /**
         * Do not ignore unexpected {@code SSH_MSG_DEBUG} messages when checking if the reception
         * action was executed as planned. Instead, such messages will cause {@link
         * #executedAsPlanned} to return {@code false}.
         *
         * <p>If both this option and {@link ReceiveOption#CHECK_ONLY_EXPECTED} have been set, the
         * latter takes precedence and {@code SSH_MSG_DEBUG} messages will still be ignored.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-11.2">RFC 4253,
         *     section 11.3 "Debug Message"</a>
         */
        FAIL_ON_UNEXPECTED_DEBUG_MESSAGES;

        public static Set<ReceiveOption> bundle(ReceiveOption... receiveOptions) {
            return new HashSet<>(Arrays.asList(receiveOptions));
        }
    }
}
