/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;
import javax.xml.bind.annotation.XmlAttribute;

public class ChannelOpenMessage extends SshMessage<ChannelOpenMessage> {

    private ModifiableInteger channelTypeLength;
    private ModifiableString channelType;
    private String transferChannelType;
    private ModifiableInteger windowSize;
    private Integer transferWindowSize;
    private ModifiableInteger packetSize;
    private Integer transferPacketSize;
    private ModifiableInteger modSenderChannel;

    @XmlAttribute(name = "channel")
    private Integer senderChannel;

    public ChannelOpenMessage() {
        super(MessageIDConstant.SSH_MSG_CHANNEL_OPEN);
    }

    public ChannelOpenMessage(Integer senderChannel) {
        super(MessageIDConstant.SSH_MSG_CHANNEL_OPEN);
        setSenderChannel(senderChannel);
    }

    public ChannelOpenMessage(
            Integer senderChannel, String channelType, Integer windowSize, Integer packetSize) {
        super(MessageIDConstant.SSH_MSG_CHANNEL_OPEN);
        setSenderChannel(senderChannel);
        setTransferChannelType(channelType);
        setTransferWindowSize(windowSize);
        setTransferPacketSize(packetSize);
    }

    public ChannelOpenMessage(
            Integer senderChannel,
            ChannelType channelType,
            Integer windowSize,
            Integer packetSize) {
        super(MessageIDConstant.SSH_MSG_CHANNEL_OPEN);
        setSenderChannel(senderChannel);
        setTransferChannelType(channelType);
        setTransferWindowSize(windowSize);
        setTransferPacketSize(packetSize);
    }

    public ModifiableInteger getChannelTypeLength() {
        return channelTypeLength;
    }

    public void setChannelTypeLength(ModifiableInteger channelTypeLength) {
        this.channelTypeLength = channelTypeLength;
    }

    public void setChannelTypeLength(int channelTypeLength) {
        this.channelTypeLength =
                ModifiableVariableFactory.safelySetValue(this.channelTypeLength, channelTypeLength);
    }

    public ModifiableString getChannelType() {
        return channelType;
    }

    public void setChannelType(ModifiableString channelType) {
        setChannelType(channelType, false);
    }

    public void setChannelType(String channelType) {
        setChannelType(channelType, false);
    }

    public void setChannelType(ChannelType channelType) {
        setChannelType(channelType.toString(), false);
    }

    public void setChannelType(ModifiableString channelType, boolean adjustLengthField) {
        if (adjustLengthField) {
            setChannelTypeLength(channelType.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.channelType = channelType;
    }

    public void setChannelType(String channelType, boolean adjustLengthField) {
        if (adjustLengthField) {
            setChannelTypeLength(channelType.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.channelType = ModifiableVariableFactory.safelySetValue(this.channelType, channelType);
    }

    public void setChannelType(ChannelType channelType, boolean adjustLengthField) {
        setChannelType(channelType.toString(), adjustLengthField);
    }

    public String getTransferChannelType() {
        return transferChannelType;
    }

    public void setTransferChannelType(String transferChannelType) {
        this.transferChannelType = transferChannelType;
    }

    public void setTransferChannelType(ChannelType transferChannelType) {
        setTransferChannelType(channelType.toString());
    }

    public ModifiableInteger getModSenderChannel() {
        return modSenderChannel;
    }

    public void setModSenderChannel(ModifiableInteger modSenderChannel) {
        this.modSenderChannel = modSenderChannel;
    }

    public void setModSenderChannel(int modSenderChannel) {
        this.modSenderChannel =
                ModifiableVariableFactory.safelySetValue(this.modSenderChannel, modSenderChannel);
    }

    public ModifiableInteger getWindowSize() {
        return windowSize;
    }

    public void setWindowSize(ModifiableInteger windowSize) {
        this.windowSize = windowSize;
    }

    public void setWindowSize(int windowSize) {
        this.windowSize = ModifiableVariableFactory.safelySetValue(this.windowSize, windowSize);
    }

    public ModifiableInteger getPacketSize() {
        return packetSize;
    }

    public void setPacketSize(ModifiableInteger packetSize) {
        this.packetSize = packetSize;
    }

    public void setPacketSize(int packetSize) {
        this.packetSize = ModifiableVariableFactory.safelySetValue(this.packetSize, packetSize);
    }

    public Integer getTransferPacketSize() {
        return transferPacketSize;
    }

    public void setTransferPacketSize(int transferPacketSize) {
        this.transferPacketSize = transferPacketSize;
    }

    public Integer getTransferWindowSize() {
        return transferWindowSize;
    }

    public void setTransferWindowSize(int transferWindowSize) {
        this.transferWindowSize = transferWindowSize;
    }

    public Integer getSenderChannel() {
        return senderChannel;
    }

    public void setSenderChannel(int senderChannel) {
        this.senderChannel = senderChannel;
    }

    @Override
    public ChannelOpenMessageHandler getHandler(SshContext context) {
        return new ChannelOpenMessageHandler(context, this);
    }
}
