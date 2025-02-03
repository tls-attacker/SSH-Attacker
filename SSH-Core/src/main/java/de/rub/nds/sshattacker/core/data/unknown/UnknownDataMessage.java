/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.unknown;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.data.DataMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UnknownDataMessage extends DataMessage<UnknownDataMessage> {

    private ModifiableByteArray payload;

    public UnknownDataMessage() {
        super();
    }

    public UnknownDataMessage(UnknownDataMessage other) {
        super(other);
        payload = other.payload != null ? other.payload.createCopy() : null;
    }

    @Override
    public UnknownDataMessage createCopy() {
        return new UnknownDataMessage(this);
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
        this.payload = ModifiableVariableFactory.softlySetValue(this.payload, payload);
    }

    @Override
    public String toCompactString() {
        return getClass().getSimpleName();
    }

    public static final UnknownDataMessageHandler HANDLER = new UnknownDataMessageHandler();

    @Override
    public UnknownDataMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UnknownDataMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return UnknownDataMessageHandler.SERIALIZER.serialize(this);
    }
}
