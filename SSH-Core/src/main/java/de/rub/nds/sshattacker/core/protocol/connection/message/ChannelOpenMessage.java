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
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;

import jakarta.xml.bind.annotation.XmlAttribute;

import java.nio.charset.StandardCharsets;

public abstract class ChannelOpenMessage<T extends ChannelOpenMessage<T>> extends SshMessage<T> {

    private ModifiableInteger channelTypeLength;
    private ModifiableString channelType;
    private ModifiableInteger windowSize;
    private ModifiableInteger packetSize;
    private ModifiableInteger senderChannelId;

    @XmlAttribute(name = "channel")
    private Integer configSenderChannelId;

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
        this.channelType = channelType;
        if (adjustLengthField) {
            setChannelTypeLength(
                    this.channelType.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setChannelType(String channelType, boolean adjustLengthField) {
        this.channelType = ModifiableVariableFactory.safelySetValue(this.channelType, channelType);
        if (adjustLengthField) {
            setChannelTypeLength(
                    this.channelType.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setChannelType(ChannelType channelType, boolean adjustLengthField) {
        setChannelType(channelType.toString(), adjustLengthField);
    }

    public ModifiableInteger getSenderChannelId() {
        return senderChannelId;
    }

    public void setSenderChannelId(ModifiableInteger senderChannelId) {
        this.senderChannelId = senderChannelId;
    }

    public void setSenderChannelId(int modSenderChannel) {
        senderChannelId =
                ModifiableVariableFactory.safelySetValue(senderChannelId, modSenderChannel);
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

    public Integer getConfigSenderChannelId() {
        return configSenderChannelId;
    }

    public void setConfigSenderChannelId(int configSenderChannelId) {
        this.configSenderChannelId = configSenderChannelId;
    }
}
