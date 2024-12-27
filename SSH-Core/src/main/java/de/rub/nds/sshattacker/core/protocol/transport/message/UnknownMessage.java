/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.UnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UnknownMessage extends SshMessage<UnknownMessage> {

    private ModifiableByteArray payload;

    public UnknownMessage() {
        super();
    }

    public UnknownMessage(UnknownMessage other) {
        super(other);
        payload = other.payload != null ? other.payload.createCopy() : null;
    }

    @Override
    public UnknownMessage createCopy() {
        return new UnknownMessage(this);
    }

    public ModifiableByteArray getPayload() {
        return payload;
    }

    public void setPayload(ModifiableByteArray payload) {
        this.payload = payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    public void setSoftlyPayload(byte[] payload) {
        if (this.payload == null || this.payload.getOriginalValue() == null) {
            this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
        }
    }

    @Override
    public String toCompactString() {
        if (messageId != null && messageId.getValue() != null) {
            return "UnknownMessage (" + MessageIdConstant.getNameById(messageId.getValue()) + ")";
        }
        return "UnknownMessage (no id set)";
    }

    @Override
    public UnknownMessageHandler getHandler(SshContext context) {
        return new UnknownMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UnknownMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
