/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessage;
import de.rub.nds.sshattacker.core.data.sftp.handler.SftpUnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpUnknownMessage extends SftpMessage<SftpUnknownMessage> {

    private ModifiableByteArray payload;

    public SftpUnknownMessage() {
        super();
    }

    public SftpUnknownMessage(SftpUnknownMessage other) {
        super(other);
        payload = other.payload != null ? other.payload.createCopy() : null;
    }

    @Override
    public SftpUnknownMessage createCopy() {
        return new SftpUnknownMessage(this);
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
        if (packetType != null && packetType.getValue() != null) {
            return "SftpUnknownMessage ("
                    + SftpPacketTypeConstant.getNameById(packetType.getValue())
                    + ")";
        }
        return "SftpUnknownMessage (no id set)";
    }

    @Override
    public SftpUnknownMessageHandler getHandler(SshContext context) {
        return new SftpUnknownMessageHandler(context, this);
    }
}
