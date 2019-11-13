package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.GlobalRequestMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.GlobalRequestMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.GlobalRequestMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class GlobalRequestMessage extends Message {

    private ModifiableInteger requestNameLength;
    private ModifiableString requestName;
    private ModifiableByte wantReply;
    private ModifiableByteArray payload;

    public ModifiableInteger getRequestNameLength() {
        return requestNameLength;
    }

    public void setRequestNameLength(ModifiableInteger requestNameLength) {
        this.requestNameLength = requestNameLength;
    }

    public void setRequestNameLength(int requestNameLength) {
        this.requestNameLength = ModifiableVariableFactory.safelySetValue(this.requestNameLength, requestNameLength);
    }

    public ModifiableString getRequestName() {
        return requestName;
    }

    public void setRequestName(ModifiableString requestName) {
        this.requestName = requestName;
    }

    public void setRequestName(String requestName) {
        this.requestName = ModifiableVariableFactory.safelySetValue(this.requestName, requestName);
    }

    public ModifiableByte getWantReply() {
        return wantReply;
    }

    public void setWantReply(ModifiableByte wantReply) {
        this.wantReply = wantReply;
    }

    public void setWantReply(byte wantReply) {
        this.wantReply = ModifiableVariableFactory.safelySetValue(this.wantReply, wantReply);
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
        return new GlobalRequestMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new GlobalRequestMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new GlobalRequestMessagePreparator(context, this);
    }

}
