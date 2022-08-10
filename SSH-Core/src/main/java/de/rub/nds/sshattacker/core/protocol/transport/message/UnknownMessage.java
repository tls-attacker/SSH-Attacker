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

public class UnknownMessage extends SshMessage<UnknownMessage> {
    private ModifiableByteArray payload;

    public UnknownMessage() {
        super(MessageIdConstant.UNKNOWN);
        this.setPayload(new byte[] {});
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
        return "UnknownMessage (" + MessageIdConstant.getNameById(messageId.getValue()) + ")";
    }

    @Override
    public UnknownMessageHandler getHandler(SshContext context) {
        return new UnknownMessageHandler(context, this);
    }
}
