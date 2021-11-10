/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
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
                @XmlElement(type = ChannelDataMessage.class, name = "ChannelDataMessage"),
                @XmlElement(type = ChannelCloseMessage.class, name = "ChannelCloseMessage"),
                @XmlElement(type = ChannelDataMessage.class, name = "ChannelDataMessage"),
                @XmlElement(type = ChannelEofMessage.class, name = "ChannelEofMessage"),
                @XmlElement(
                        type = ChannelExtendedDataMessage.class,
                        name = "ChannelExtendedDataMessage"),
                @XmlElement(type = ChannelFailureMessage.class, name = "ChannelFailureMessage"),
                @XmlElement(
                        type = ChannelOpenConfirmationMessage.class,
                        name = "ChannelOpenConfirmationMessage"),
                @XmlElement(
                        type = ChannelOpenFailureMessage.class,
                        name = "ChannelOpenFailureMessage"),
                @XmlElement(type = ChannelOpenMessage.class, name = "ChannelOpenMessage"),
                @XmlElement(
                        type = ChannelRequestExecMessage.class,
                        name = "ChannelRequestExecMessage"),
                @XmlElement(type = ChannelSuccessMessage.class, name = "ChannelSuccessMessage"),
                @XmlElement(
                        type = ChannelWindowAdjustMessage.class,
                        name = "ChannelWindowAdjustMessage"),
                @XmlElement(type = DebugMessage.class, name = "DebugMessage"),
                @XmlElement(
                        type = DhGexKeyExchangeGroupMessage.class,
                        name = "DhGexKeyExchangeGroupMessage"),
                @XmlElement(
                        type = DhGexKeyExchangeInitMessage.class,
                        name = "DhGexKeyExchangeInitMessage"),
                @XmlElement(
                        type = DhGexKeyExchangeOldRequestMessage.class,
                        name = "DhGexKeyExchangeOldRequestMessage"),
                @XmlElement(
                        type = DhGexKeyExchangeReplyMessage.class,
                        name = "DhGexKeyExchangeReplyMessage"),
                @XmlElement(
                        type = DhGexKeyExchangeRequestMessage.class,
                        name = "DhGexKeyExchangeRequestMessage"),
                @XmlElement(
                        type = DhKeyExchangeInitMessage.class,
                        name = "DhKeyExchangeInitMessage"),
                @XmlElement(
                        type = DhKeyExchangeReplyMessage.class,
                        name = "DhKeyExchangeReplyMessage"),
                @XmlElement(type = DisconnectMessage.class, name = "DisconnectMessage"),
                @XmlElement(
                        type = EcdhKeyExchangeInitMessage.class,
                        name = "EcdhKeyExchangeInitMessage"),
                @XmlElement(
                        type = EcdhKeyExchangeReplyMessage.class,
                        name = "EcdhKeyExchangeReplyMessage"),
                @XmlElement(type = IgnoreMessage.class, name = "IgnoreMessage"),
                @XmlElement(type = KeyExchangeInitMessage.class, name = "KeyExchangeInitMessage"),
                @XmlElement(type = SshMessage.class, name = "Message"),
                @XmlElement(type = NewKeysMessage.class, name = "NewKeysMessage"),
                @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
                @XmlElement(type = RequestFailureMessage.class, name = "RequestFailureMessage"),
                @XmlElement(type = RequestSuccessMessage.class, name = "RequestSuccessMessage"),
                @XmlElement(
                        type = RsaKeyExchangePubkeyMessage.class,
                        name = "RsaKeyExchangePubkeyMessage"),
                @XmlElement(type = ServiceAcceptMessage.class, name = "ServiceAcceptMessage"),
                @XmlElement(type = ServiceRequestMessage.class, name = "ServiceRequestMessage"),
                @XmlElement(type = UnimplementedMessage.class, name = "UnimplementedMessage"),
                @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
                @XmlElement(type = UserAuthBannerMessage.class, name = "UserAuthBannerMessage"),
                @XmlElement(type = UserAuthFailureMessage.class, name = "UserAuthFailureMessage"),
                @XmlElement(type = UserAuthPasswordMessage.class, name = "UserAuthPasswordMessage"),
                @XmlElement(type = UserAuthSuccessMessage.class, name = "UserAuthSuccessMessage"),
                @XmlElement(type = VersionExchangeMessage.class, name = "VersionExchangeMessage"),
                @XmlElement(type = TcpIpForwardRequestMessage.class, name = "TcpIpForwardRequestMessage"),
                @XmlElement(type = TcpIpForwardCancelMessage.class, name = "TcpIpForwardCancelMessage")
            })
    protected List<ProtocolMessage<?>> messages = new ArrayList<>();

    @XmlTransient protected final ReceiveMessageHelper receiveMessageHelper;

    @XmlTransient protected final SendMessageHelper sendMessageHelper;

    public MessageAction() {
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(List<ProtocolMessage<?>> messages) {
        this.messages = new ArrayList<>(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(ProtocolMessage<?>... messages) {
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
    }

    private void initEmptyLists() {
        if (messages == null) {
            messages = new ArrayList<>();
        }
    }
}
