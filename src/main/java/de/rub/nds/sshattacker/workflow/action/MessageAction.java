package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.protocol.helper.ReceiveMessageHelper;
import de.rub.nds.sshattacker.protocol.helper.SendMessageHelper;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.Message;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlTransient;

public abstract class MessageAction extends ConnectionBoundAction {

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
