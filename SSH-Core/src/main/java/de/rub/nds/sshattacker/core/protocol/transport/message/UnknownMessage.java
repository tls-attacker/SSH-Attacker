/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.handler.UnknownMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.UnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UnknownMessage extends Message<UnknownMessage> {

    private ModifiableByteArray payload;

    public UnknownMessage() {
        super();
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
    public String toCompactString() {
        return "UnknownMessage (" + MessageIDConstant.getNameByID(messageID.getValue()) + ")";
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
        throw new NotImplementedException("UnknownMessage::getPreparator");
    }
}
