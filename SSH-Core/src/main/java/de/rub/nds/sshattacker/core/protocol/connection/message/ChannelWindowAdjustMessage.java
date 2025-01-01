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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelWindowAdjustMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelWindowAdjustMessage extends ChannelMessage<ChannelWindowAdjustMessage>
        implements HasSentHandler {

    private ModifiableInteger bytesToAdd;

    public ChannelWindowAdjustMessage() {
        super();
    }

    public ChannelWindowAdjustMessage(ChannelWindowAdjustMessage other) {
        super(other);
        bytesToAdd = other.bytesToAdd != null ? other.bytesToAdd.createCopy() : null;
    }

    @Override
    public ChannelWindowAdjustMessage createCopy() {
        return new ChannelWindowAdjustMessage(this);
    }

    public ModifiableInteger getBytesToAdd() {
        return bytesToAdd;
    }

    public void setBytesToAdd(ModifiableInteger bytesToAdd) {
        this.bytesToAdd = bytesToAdd;
    }

    public void setBytesToAdd(int bytesToAdd) {
        this.bytesToAdd = ModifiableVariableFactory.safelySetValue(this.bytesToAdd, bytesToAdd);
    }

    public void setSoftlyBytesToAdd(int bytesToAdd) {
        if (this.bytesToAdd == null || this.bytesToAdd.getOriginalValue() == null) {
            this.bytesToAdd = ModifiableVariableFactory.safelySetValue(this.bytesToAdd, bytesToAdd);
        }
    }

    public static final ChannelWindowAdjustMessageHandler HANDLER =
            new ChannelWindowAdjustMessageHandler();

    @Override
    public ChannelWindowAdjustMessageHandler getHandler() {
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
        ChannelWindowAdjustMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelWindowAdjustMessageHandler.SERIALIZER.serialize(this);
    }
}
