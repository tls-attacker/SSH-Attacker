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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.preparator.GlobalRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.serializer.GlobalRequestMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.handler.GlobalRequestMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestMessage extends Message<GlobalRequestMessage> {

    private ModifiableString requestName;
    private ModifiableByte wantReply;
    private ModifiableByteArray payload;

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
    public GlobalRequestMessageHandler getHandler(SshContext context) {
        return new GlobalRequestMessageHandler(context);
    }

    @Override
    public GlobalRequestMessageSerializer getSerializer() {
        return new GlobalRequestMessageSerializer(this);
    }

    @Override
    public GlobalRequestMessagePreparator getPreparator(SshContext context) {
        return new GlobalRequestMessagePreparator(context, this);
    }

}
