/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.util.ReceiveMessageHelper;
import de.rub.nds.sshattacker.core.protocol.util.SendMessageHelper;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;

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
    @XmlElements(value = { @XmlElement(type = ChannelDataMessage.class, name = "ChannelDataMessage"),
            @XmlElement(type = ChannelCloseMessage.class, name = "ChannelCloseMessage"),
            @XmlElement(type = ChannelDataMessage.class, name = "ChannelDataMessage"),
            @XmlElement(type = ChannelEofMessage.class, name = "ChannelEofMessage"),
            @XmlElement(type = ChannelExtendedDataMessage.class, name = "ChannelExtendedDataMessage"),
            @XmlElement(type = ChannelFailureMessage.class, name = "ChannelFailureMessage"),
            @XmlElement(type = ChannelOpenConfirmationMessage.class, name = "ChannelOpenConfirmationMessage"),
            @XmlElement(type = ChannelOpenFailureMessage.class, name = "ChannelOpenFailureMessage"),
            @XmlElement(type = ChannelOpenMessage.class, name = "ChannelOpenMessage"),
            @XmlElement(type = ChannelRequestMessage.class, name = "ChannelRequestMessage"),
            @XmlElement(type = ChannelSuccessMessage.class, name = "ChannelSuccessMessage"),
            @XmlElement(type = ChannelWindowAdjustMessage.class, name = "ChannelWindowAdjustMessage"),
            @XmlElement(type = DebugMessage.class, name = "DebugMessage"),
            @XmlElement(type = DhGexKeyExchangeGroupMessage.class, name = "DhGexKeyExchangeGroupMessage"),
            @XmlElement(type = DhGexKeyExchangeInitMessage.class, name = "DhGexKeyExchangeInitMessage"),
            @XmlElement(type = DhGexKeyExchangeOldRequestMessage.class, name = "DhGexKeyExchangeOldRequestMessage"),
            @XmlElement(type = DhGexKeyExchangeReplyMessage.class, name = "DhGexKeyExchangeReplyMessage"),
            @XmlElement(type = DhGexKeyExchangeRequestMessage.class, name = "DhGexKeyExchangeRequestMessage"),
            @XmlElement(type = DhKeyExchangeInitMessage.class, name = "DhKeyExchangeInitMessage"),
            @XmlElement(type = DhKeyExchangeReplyMessage.class, name = "DhKeyExchangeReplyMessage"),
            @XmlElement(type = DisconnectMessage.class, name = "DisconnectMessage"),
            @XmlElement(type = EcdhKeyExchangeInitMessage.class, name = "EcdhKeyExchangeInitMessage"),
            @XmlElement(type = EcdhKeyExchangeReplyMessage.class, name = "EcdhKeyExchangeReplyMessage"),
            @XmlElement(type = GlobalRequestMessage.class, name = "GlobalRequestMessage"),
            @XmlElement(type = IgnoreMessage.class, name = "IgnoreMessage"),
            @XmlElement(type = KeyExchangeInitMessage.class, name = "KeyExchangeInitMessage"),
            @XmlElement(type = Message.class, name = "Message"),
            @XmlElement(type = NewKeysMessage.class, name = "NewKeysMessage"),
            @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
            @XmlElement(type = RequestFailureMessage.class, name = "RequestFailureMessage"),
            @XmlElement(type = RequestSuccessMessage.class, name = "RequestSuccessMessage"),
            @XmlElement(type = ServiceAcceptMessage.class, name = "ServiceAcceptMessage"),
            @XmlElement(type = ServiceRequestMessage.class, name = "ServiceRequestMessage"),
            @XmlElement(type = UnimplementedMessage.class, name = "UnimplementedMessage"),
            @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
            @XmlElement(type = UserAuthBannerMessage.class, name = "UserAuthBannerMessage"),
            @XmlElement(type = UserAuthFailureMessage.class, name = "UserAuthFailureMessage"),
            @XmlElement(type = UserAuthPasswordMessage.class, name = "UserAuthPasswordMessage"),
            @XmlElement(type = UserAuthSuccessMessage.class, name = "UserAuthSuccessMessage"),
            @XmlElement(type = VersionExchangeMessage.class, name = "VersionExchangeMessage") })
    protected List<Message<?>> messages = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    protected List<BinaryPacket> binaryPackets = new ArrayList<>();

    @XmlTransient
    protected ReceiveMessageHelper receiveMessageHelper;

    @XmlTransient
    protected SendMessageHelper sendMessageHelper;

    public MessageAction() {
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(List<Message<?>> messages) {
        this.messages = new ArrayList<>(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(Message<?>... messages) {
        this.messages = new ArrayList<>(Arrays.asList(messages));
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias) {
        super(connectionAlias);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias, List<Message<?>> messages) {
        super(connectionAlias);
        this.messages = new ArrayList<>(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias, Message<?>... messages) {
        this(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    public void setReceiveMessageHelper(ReceiveMessageHelper receiveMessageHelper) {
        this.receiveMessageHelper = receiveMessageHelper;
    }

    public void setSendMessageHelper(SendMessageHelper sendMessageHelper) {
        this.sendMessageHelper = sendMessageHelper;
    }

    public String getReadableString(Message<?>... messages) {
        return getReadableString(Arrays.asList(messages));
    }

    public String getReadableString(List<Message<?>> messages) {
        return getReadableString(messages, false);
    }

    public String getReadableString(List<Message<?>> messages, Boolean verbose) {
        StringBuilder builder = new StringBuilder();
        if (messages == null) {
            return builder.toString();
        }
        for (Message<?> message : messages) {
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

    public List<Message<?>> getMessages() {
        return messages;
    }

    public void setMessages(List<Message<?>> messages) {
        this.messages = messages;
    }

    public void setMessages(Message<?>... messages) {
        this.messages = new ArrayList<>(Arrays.asList(messages));
    }

    public List<BinaryPacket> getBinaryPackets() {
        return binaryPackets;
    }

    public void setBinaryPackets(List<BinaryPacket> binaryPackets) {
        this.binaryPackets = binaryPackets;
    }

    public void setRecords(BinaryPacket... binaryPackets) {
        this.binaryPackets = new ArrayList<>(Arrays.asList(binaryPackets));
    }

    public void clearRecords() {
        this.binaryPackets = null;
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
        if (binaryPackets == null || binaryPackets.isEmpty()) {
            binaryPackets = null;
        }
    }

    private void initEmptyLists() {
        if (messages == null) {
            messages = new ArrayList<>();
        }
        if (binaryPackets == null) {
            binaryPackets = new ArrayList<>();
        }
    }

}
