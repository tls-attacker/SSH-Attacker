package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.UnknownMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class UnknownMessage extends Message {

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
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String toCompactString() {
        return "UnknownMessage";
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
    public Handler getHandler(SshContext context) {
        return new UnknownMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new UnknownMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
