package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.protocol.helper.ReceiveMessageHelper;
import de.rub.nds.sshattacker.protocol.helper.SendMessageHelper;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.ChannelDataMessage;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.protocol.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.protocol.message.DisconnectMessage;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.Message;
import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;
import de.rub.nds.sshattacker.protocol.message.ProtocolMessage;
import de.rub.nds.sshattacker.protocol.message.ServiceAcceptMessage;
import de.rub.nds.sshattacker.protocol.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.protocol.message.UnknownMessage;
import de.rub.nds.sshattacker.protocol.message.UserauthPasswordMessage;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;

public abstract class MessageAction extends ConnectionBoundAction {

    @XmlElementWrapper
    @XmlElements(value = {
        @XmlElement(type = ChannelDataMessage.class, name = "ChannelDataMessage"),
        @XmlElement(type = ChannelOpenConfirmationMessage.class, name = "ChannelOpenConfirmationMessage"),
        @XmlElement(type = ChannelOpenMessage.class, name = "ChannelOpenMessage"),
        @XmlElement(type = ChannelRequestMessage.class, name = "ChannelRequestMessage"),
        @XmlElement(type = ClientInitMessage.class, name = "ClientInitMessage"),
        @XmlElement(type = DisconnectMessage.class, name = "DisconnectMessage"),
        @XmlElement(type = EcdhKeyExchangeInitMessage.class, name = "EcdhKeyExchangeInitMessage"),
        @XmlElement(type = EcdhKeyExchangeReplyMessage.class, name = "EcdhKeyExchangeReplyMessage"),
        @XmlElement(type = KeyExchangeInitMessage.class, name = "KeyExchangeInitMessage"),
        @XmlElement(type = Message.class, name = "Message"),
        @XmlElement(type = NewKeysMessage.class, name = "NewKeysMessage"),
        @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
        @XmlElement(type = ServiceAcceptMessage.class, name = "ServiceAcceptMessage"),
        @XmlElement(type = ServiceRequestMessage.class, name = "ServiceRequestMessage"),
        @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
        @XmlElement(type = UserauthPasswordMessage.class, name = "UserauthPasswordMessage")})
    protected List<Message> messages = new ArrayList<>();

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

    public MessageAction(List<Message> messages) {
        this.messages = new ArrayList<>(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(Message... messages) {
        this.messages = new ArrayList<>(Arrays.asList(messages));
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias) {
        super(connectionAlias);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias, List<Message> messages) {
        super(connectionAlias);
        this.messages = new ArrayList<>(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias, Message... messages) {
        this(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    public void setReceiveMessageHelper(ReceiveMessageHelper receiveMessageHelper) {
        this.receiveMessageHelper = receiveMessageHelper;
    }

    public void setSendMessageHelper(SendMessageHelper sendMessageHelper) {
        this.sendMessageHelper = sendMessageHelper;
    }

    public String getReadableString(Message... messages) {
        return getReadableString(Arrays.asList(messages));
    }

    public String getReadableString(List<Message> messages) {
        return getReadableString(messages, false);
    }

    public String getReadableString(List<Message> messages, Boolean verbose) {
        StringBuilder builder = new StringBuilder();
        if (messages == null) {
            return builder.toString();
        }
        for (Message message : messages) {
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

    public List<Message> getMessages() {
        return messages;
    }

    public void setMessages(List<Message> messages) {
        this.messages = messages;
    }

    public void setMessages(Message... messages) {
        this.messages = new ArrayList(Arrays.asList(messages));
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
