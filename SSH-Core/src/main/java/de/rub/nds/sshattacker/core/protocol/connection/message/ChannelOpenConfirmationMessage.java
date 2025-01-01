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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenConfirmationMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenConfirmationMessage extends ChannelMessage<ChannelOpenConfirmationMessage>
        implements HasSentHandler {

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

    public void setSenderChannelId(int senderChannelId) {
        this.senderChannelId =
                ModifiableVariableFactory.safelySetValue(this.senderChannelId, senderChannelId);
    }

    public void setSoftlySenderChannelId(int senderChannelId, Config config) {
        if (config.getAlwaysPrepareChannelIds()
                || this.senderChannelId == null
                || this.senderChannelId.getOriginalValue() == null) {
            this.senderChannelId =
                    ModifiableVariableFactory.safelySetValue(this.senderChannelId, senderChannelId);
        }
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

    public static final ChannelOpenConfirmationMessageHandler HANDLER =
            new ChannelOpenConfirmationMessageHandler();

    @Override
    public ChannelOpenConfirmationMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelOpenConfirmationMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelOpenConfirmationMessageHandler.SERIALIZER.serialize(this);
    }
}
