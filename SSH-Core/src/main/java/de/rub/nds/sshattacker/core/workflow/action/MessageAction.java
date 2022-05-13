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
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import de.rub.nds.sshattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.sshattacker.core.workflow.action.executor.SendMessageHelper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;

public abstract class MessageAction extends ConnectionBoundAction {

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            value = {
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
                @XmlElement(type = VersionExchangeMessage.class, name = "VersionExchange"),
                // Authentication Layer Protocol Messages
                @XmlElement(type = UserAuthBannerMessage.class, name = "UserAuthBanner"),
                @XmlElement(type = UserAuthFailureMessage.class, name = "UserAuthFailure"),
                @XmlElement(type = UserAuthPasswordMessage.class, name = "UserAuthPassword"),
                @XmlElement(type = UserAuthSuccessMessage.class, name = "UserAuthSuccess"),
                // Connection Layer Protocol Messages
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
                @XmlElement(type = ChannelRequestEnvMessage.class, name = "ChannelRequestEnv"),
                @XmlElement(type = ChannelRequestExecMessage.class, name = "ChannelRequestExec"),
                @XmlElement(
                        type = ChannelRequestExitSignalMessage.class,
                        name = "ChannelRequestExitSignal"),
                @XmlElement(
                        type = ChannelRequestExitStatusMessage.class,
                        name = "ChannelRequestExitStatus"),
                @XmlElement(type = ChannelRequestShellMessage.class, name = "ChannelRequestShell"),
                @XmlElement(
                        type = ChannelRequestSignalMessage.class,
                        name = "ChannelRequestSignal"),
                @XmlElement(type = ChannelSuccessMessage.class, name = "ChannelSuccess"),
                @XmlElement(type = ChannelWindowAdjustMessage.class, name = "ChannelWindowAdjust"),
                @XmlElement(type = NoMoreSessionsMessage.class, name = "NoMoreSessions"),
                @XmlElement(type = RequestFailureMessage.class, name = "RequestFailure"),
                @XmlElement(type = RequestSuccessMessage.class, name = "RequestSuccess"),
                @XmlElement(type = TcpIpForwardCancelMessage.class, name = "TcpIpForwardCancel"),
                @XmlElement(type = TcpIpForwardRequestMessage.class, name = "TcpIpForwardRequest"),
                // Other
                @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
                @XmlElement(
                        type = UserAuthKeyboardInteractiveMessage.class,
                        name = "UserAuthKeyboardInteractive"),
                @XmlElement(type = UserAuthInfoRequestMessage.class, name = "UserAuthInfoRequest"),
                @XmlElement(
                        type = UserAuthInfoResponseMessage.class,
                        name = "UserAuthInfoResponse"),
                @XmlElement(type = UserAuthPubkeyMessage.class, name = "UserAuthPubkey"),
            })
    protected List<ProtocolMessage<?>> messages = new ArrayList<>();

    @XmlTransient protected final ReceiveMessageHelper receiveMessageHelper;

    @XmlTransient protected final SendMessageHelper sendMessageHelper;

    public MessageAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(List<ProtocolMessage<?>> messages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.messages = new ArrayList<>(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(ProtocolMessage<?>... messages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.messages = Arrays.asList(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias) {
        super(connectionAlias);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias, List<ProtocolMessage<?>> messages) {
        super(connectionAlias);
        this.messages = new ArrayList<>(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias, ProtocolMessage<?>... messages) {
        this(connectionAlias, Arrays.asList(messages));
    }

    public String getReadableString(ProtocolMessage<?>... messages) {
        return getReadableString(Arrays.asList(messages));
    }

    public String getReadableString(List<ProtocolMessage<?>> messages) {
        return getReadableString(messages, false);
    }

    public String getReadableString(List<ProtocolMessage<?>> messages, Boolean verbose) {
        if (messages == null || messages.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
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
        return builder.deleteCharAt(builder.lastIndexOf(", ")).toString();
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
    }

    private void initEmptyLists() {
        if (messages == null) {
            messages = new ArrayList<>();
        }
    }
}
