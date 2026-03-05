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
    private ModifiableInteger senderChannelId;
    private ModifiableInteger initialWindowSize;
    private ModifiableInteger maximumPacketSize;

    @XmlAttribute(name = "localChannel")
    protected Integer configLocalChannelId;

    protected ChannelOpenMessage() {
        super();
    }

    protected ChannelOpenMessage(ChannelOpenMessage<T> other) {
        super(other);
        channelTypeLength =
                other.channelTypeLength != null ? other.channelTypeLength.createCopy() : null;
        channelType = other.channelType != null ? other.channelType.createCopy() : null;
        initialWindowSize =
                other.initialWindowSize != null ? other.initialWindowSize.createCopy() : null;
        maximumPacketSize =
                other.maximumPacketSize != null ? other.maximumPacketSize.createCopy() : null;
        senderChannelId = other.senderChannelId != null ? other.senderChannelId.createCopy() : null;
        configLocalChannelId = other.configLocalChannelId;
    }

    @Override
    public abstract ChannelOpenMessage<T> createCopy();

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

    public void setSenderChannelId(int senderChannelId) {
        this.senderChannelId =
                ModifiableVariableFactory.safelySetValue(this.senderChannelId, senderChannelId);
    }

    public ModifiableInteger getInitialWindowSize() {
        return initialWindowSize;
    }

    public void setInitialWindowSize(ModifiableInteger initialWindowSize) {
        this.initialWindowSize = initialWindowSize;
    }

    public void setInitialWindowSize(int initialWindowSize) {
        this.initialWindowSize =
                ModifiableVariableFactory.safelySetValue(this.initialWindowSize, initialWindowSize);
    }

    public ModifiableInteger getMaximumPacketSize() {
        return maximumPacketSize;
    }

    public void setMaximumPacketSize(ModifiableInteger maximumPacketSize) {
        this.maximumPacketSize = maximumPacketSize;
    }

    public void setMaximumPacketSize(int maximumPacketSize) {
        this.maximumPacketSize =
                ModifiableVariableFactory.safelySetValue(this.maximumPacketSize, maximumPacketSize);
    }

    public Integer getConfigLocalChannelId() {
        return configLocalChannelId;
    }

    public void setConfigLocalChannelId(int configLocalChannelId) {
        this.configLocalChannelId = configLocalChannelId;
    }
}
