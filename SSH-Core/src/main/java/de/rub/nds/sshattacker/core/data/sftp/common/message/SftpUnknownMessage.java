/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.handler.SftpUnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

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

    @Override
    public String toCompactString() {
        if (packetType != null && packetType.getValue() != null) {
            return "SftpUnknownMessage ("
                    + SftpPacketTypeConstant.getNameById(packetType.getValue())
                    + ")";
        }
        return "SftpUnknownMessage (no id set)";
    }

    public static final SftpUnknownMessageHandler HANDLER = new SftpUnknownMessageHandler();

    @Override
    public SftpUnknownMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpUnknownMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpUnknownMessageHandler.SERIALIZER.serialize(this);
    }
}
