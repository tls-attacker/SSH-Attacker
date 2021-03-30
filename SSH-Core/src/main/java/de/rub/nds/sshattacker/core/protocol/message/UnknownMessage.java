/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.core.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.handler.UnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UnknownMessage extends Message<UnknownMessage> {

    private ModifiableByteArray payload;

    public UnknownMessage(ModifiableByte id, ModifiableByteArray payload) {
        this.messageID = id;
        this.payload = payload;
    }

    public UnknownMessage(byte id, byte[] payload) {
        this.messageID = ModifiableVariableFactory.safelySetValue(this.messageID, id);
        this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    public UnknownMessage() {
    }

    @Override
    public String toCompactString() {
        return "UnknownMessage (" + MessageIDConstant.getNameByID(messageID.getValue()) + ")";
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

    @Override
    public UnknownMessageHandler getHandler(SshContext context) {
        return new UnknownMessageHandler(context);
    }

    @Override
    public UnknownMessageSerializer getSerializer() {
        return new UnknownMessageSerializer(this);
    }

    @Override
    public Preparator<UnknownMessage> getPreparator(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }
}
