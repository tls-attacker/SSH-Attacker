package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.RequestSuccessMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.preparator.RequestSuccessMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.RequestSuccessMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class RequestSuccessMessage extends Message {

    private ModifiableByteArray payload;

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
        return new RequestSuccessMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new RequestSuccessMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new RequestSuccessMessagePreparator(context, this);
    }

}
