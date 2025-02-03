/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.DataMessage;

public abstract class SftpMessage<T extends SftpMessage<T>> extends DataMessage<T> {

    protected ModifiableByte packetType;

    protected SftpMessage() {
        super();
    }

    protected SftpMessage(SftpMessage<T> other) {
        super(other);
        packetType = other.packetType != null ? other.packetType.createCopy() : null;
    }

    @Override
    public abstract SftpMessage<T> createCopy();

    public ModifiableByte getPacketType() {
        return packetType;
    }

    public void setPacketType(ModifiableByte packetType) {
        this.packetType = packetType;
    }

    public void setPacketType(byte packetType) {
        this.packetType = ModifiableVariableFactory.safelySetValue(this.packetType, packetType);
    }

    public void setSoftlyPacketType(byte packetType) {
        this.packetType = ModifiableVariableFactory.softlySetValue(this.packetType, packetType);
    }

    public void setPacketType(SftpPacketTypeConstant packetType) {
        setPacketType(packetType.getId());
    }

    public void setSoftlyPacketType(SftpPacketTypeConstant packetType) {
        setSoftlyPacketType(packetType.getId());
    }

    @Override
    public String toCompactString() {
        return getClass().getSimpleName();
    }
}
