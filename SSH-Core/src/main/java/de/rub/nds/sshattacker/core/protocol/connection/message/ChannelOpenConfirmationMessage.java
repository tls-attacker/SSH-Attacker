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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenConfirmationMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenConfirmationMessage extends ChannelMessage<ChannelOpenConfirmationMessage> {

    private ModifiableInteger senderChannelId;
    private ModifiableInteger windowSize;
    private ModifiableInteger packetSize;

    public ChannelOpenConfirmationMessage() {
        super();
    }

    public ChannelOpenConfirmationMessage(ChannelOpenConfirmationMessage other) {
        super(other);
        senderChannelId = other.senderChannelId != null ? other.senderChannelId.createCopy() : null;
        windowSize = other.windowSize != null ? other.windowSize.createCopy() : null;
        packetSize = other.packetSize != null ? other.packetSize.createCopy() : null;
    }

    @Override
    public ChannelOpenConfirmationMessage createCopy() {
        return new ChannelOpenConfirmationMessage(this);
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

    public void setSoftlyWindowSize(int windowSize) {
        if (this.windowSize == null || this.windowSize.getOriginalValue() == null) {
            this.windowSize = ModifiableVariableFactory.safelySetValue(this.windowSize, windowSize);
        }
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

    public void setSoftlyPacketSize(int packetSize) {
        if (this.packetSize == null || this.packetSize.getOriginalValue() == null) {
            this.packetSize = ModifiableVariableFactory.safelySetValue(this.packetSize, packetSize);
        }
    }

    @Override
    public ChannelOpenConfirmationMessageHandler getHandler(SshContext context) {
        return new ChannelOpenConfirmationMessageHandler(context, this);
    }
}
