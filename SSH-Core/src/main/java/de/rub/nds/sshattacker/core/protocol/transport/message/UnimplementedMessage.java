/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.UnimplementedMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UnimplementedMessage extends SshMessage<UnimplementedMessage> {

    private ModifiableInteger sequenceNumber;

    public UnimplementedMessage() {
        super();
    }

    public UnimplementedMessage(UnimplementedMessage other) {
        super(other);
        sequenceNumber = other.sequenceNumber != null ? other.sequenceNumber.createCopy() : null;
    }

    @Override
    public UnimplementedMessage createCopy() {
        return new UnimplementedMessage(this);
    }

    public ModifiableInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber =
                ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    public void setSoftlySequenceNumber(int sequenceNumber) {
        if (this.sequenceNumber == null || this.sequenceNumber.getOriginalValue() == null) {
            this.sequenceNumber =
                    ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
        }
    }

    @Override
    public UnimplementedMessageHandler getHandler(SshContext context) {
        return new UnimplementedMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UnimplementedMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return UnimplementedMessageHandler.SERIALIZER.serialize(this);
    }
}
