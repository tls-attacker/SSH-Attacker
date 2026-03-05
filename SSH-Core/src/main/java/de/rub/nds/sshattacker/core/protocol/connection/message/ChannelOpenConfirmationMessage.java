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
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenConfirmationMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenConfirmationMessage extends ChannelMessage<ChannelOpenConfirmationMessage>
        implements HasSentHandler {

    private ModifiableInteger senderChannelId;
    private ModifiableInteger initialWindowSize;
    private ModifiableInteger maximumPacketSize;

    public ChannelOpenConfirmationMessage() {
        super();
    }

    public ChannelOpenConfirmationMessage(ChannelOpenConfirmationMessage other) {
        super(other);
        senderChannelId = other.senderChannelId != null ? other.senderChannelId.createCopy() : null;
        initialWindowSize =
                other.initialWindowSize != null ? other.initialWindowSize.createCopy() : null;
        maximumPacketSize =
                other.maximumPacketSize != null ? other.maximumPacketSize.createCopy() : null;
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
