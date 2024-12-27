/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_response.SftpResponseSpaceAvailableMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseSpaceAvailableMessage
        extends SftpResponseMessage<SftpResponseSpaceAvailableMessage> {

    private ModifiableLong bytesOnDevice;
    private ModifiableLong unusedBytesOnDevice;
    private ModifiableLong bytesAvailableToUser;
    private ModifiableLong unusedBytesAvailableToUser;
    private ModifiableInteger bytesPerAllocationUnit;

    public SftpResponseSpaceAvailableMessage() {
        super();
    }

    public SftpResponseSpaceAvailableMessage(SftpResponseSpaceAvailableMessage other) {
        super(other);
        bytesOnDevice = other.bytesOnDevice != null ? other.bytesOnDevice.createCopy() : null;
        unusedBytesOnDevice =
                other.unusedBytesOnDevice != null ? other.unusedBytesOnDevice.createCopy() : null;
        bytesAvailableToUser =
                other.bytesAvailableToUser != null ? other.bytesAvailableToUser.createCopy() : null;
        unusedBytesAvailableToUser =
                other.unusedBytesAvailableToUser != null
                        ? other.unusedBytesAvailableToUser.createCopy()
                        : null;
        bytesPerAllocationUnit =
                other.bytesPerAllocationUnit != null
                        ? other.bytesPerAllocationUnit.createCopy()
                        : null;
    }

    @Override
    public SftpResponseSpaceAvailableMessage createCopy() {
        return new SftpResponseSpaceAvailableMessage(this);
    }

    public ModifiableLong getBytesOnDevice() {
        return bytesOnDevice;
    }

    public void setBytesOnDevice(ModifiableLong bytesOnDevice) {
        this.bytesOnDevice = bytesOnDevice;
    }

    public void setBytesOnDevice(long bytesOnDevice) {
        this.bytesOnDevice =
                ModifiableVariableFactory.safelySetValue(this.bytesOnDevice, bytesOnDevice);
    }

    public void setSoftlyBytesOnDevice(long bytesOnDevice) {
        if (this.bytesOnDevice == null || this.bytesOnDevice.getOriginalValue() == null) {
            this.bytesOnDevice =
                    ModifiableVariableFactory.safelySetValue(this.bytesOnDevice, bytesOnDevice);
        }
    }

    public ModifiableLong getUnusedBytesOnDevice() {
        return unusedBytesOnDevice;
    }

    public void setUnusedBytesOnDevice(ModifiableLong unusedBytesOnDevice) {
        this.unusedBytesOnDevice = unusedBytesOnDevice;
    }

    public void setUnusedBytesOnDevice(long unusedBytesOnDevice) {
        this.unusedBytesOnDevice =
                ModifiableVariableFactory.safelySetValue(
                        this.unusedBytesOnDevice, unusedBytesOnDevice);
    }

    public void setSoftlyUnusedBytesOnDevice(long unusedBytesOnDevice) {
        if (this.unusedBytesOnDevice == null
                || this.unusedBytesOnDevice.getOriginalValue() == null) {
            this.unusedBytesOnDevice =
                    ModifiableVariableFactory.safelySetValue(
                            this.unusedBytesOnDevice, unusedBytesOnDevice);
        }
    }

    public ModifiableLong getBytesAvailableToUser() {
        return bytesAvailableToUser;
    }

    public void setBytesAvailableToUser(ModifiableLong bytesAvailableToUser) {
        this.bytesAvailableToUser = bytesAvailableToUser;
    }

    public void setBytesAvailableToUser(long bytesAvailableToUser) {
        this.bytesAvailableToUser =
                ModifiableVariableFactory.safelySetValue(
                        this.bytesAvailableToUser, bytesAvailableToUser);
    }

    public void setSoftlyBytesAvailableToUser(long bytesAvailableToUser) {
        if (this.bytesAvailableToUser == null
                || this.bytesAvailableToUser.getOriginalValue() == null) {
            this.bytesAvailableToUser =
                    ModifiableVariableFactory.safelySetValue(
                            this.bytesAvailableToUser, bytesAvailableToUser);
        }
    }

    public ModifiableLong getUnusedBytesAvailableToUser() {
        return unusedBytesAvailableToUser;
    }

    public void setUnusedBytesAvailableToUser(ModifiableLong unusedBytesAvailableToUser) {
        this.unusedBytesAvailableToUser = unusedBytesAvailableToUser;
    }

    public void setUnusedBytesAvailableToUser(long unusedBytesAvailableToUser) {
        this.unusedBytesAvailableToUser =
                ModifiableVariableFactory.safelySetValue(
                        this.unusedBytesAvailableToUser, unusedBytesAvailableToUser);
    }

    public void setSoftlyUnusedBytesAvailableToUser(long unusedBytesAvailableToUser) {
        if (this.unusedBytesAvailableToUser == null
                || this.unusedBytesAvailableToUser.getOriginalValue() == null) {
            this.unusedBytesAvailableToUser =
                    ModifiableVariableFactory.safelySetValue(
                            this.unusedBytesAvailableToUser, unusedBytesAvailableToUser);
        }
    }

    public ModifiableInteger getBytesPerAllocationUnit() {
        return bytesPerAllocationUnit;
    }

    public void setBytesPerAllocationUnit(ModifiableInteger bytesPerAllocationUnit) {
        this.bytesPerAllocationUnit = bytesPerAllocationUnit;
    }

    public void setBytesPerAllocationUnit(int bytesPerAllocationUnit) {
        this.bytesPerAllocationUnit =
                ModifiableVariableFactory.safelySetValue(
                        this.bytesPerAllocationUnit, bytesPerAllocationUnit);
    }

    public void setSoftlyBytesPerAllocationUnit(int bytesPerAllocationUnit) {
        if (this.bytesPerAllocationUnit == null
                || this.bytesPerAllocationUnit.getOriginalValue() == null) {
            this.bytesPerAllocationUnit =
                    ModifiableVariableFactory.safelySetValue(
                            this.bytesPerAllocationUnit, bytesPerAllocationUnit);
        }
    }

    @Override
    public SftpResponseSpaceAvailableMessageHandler getHandler(SshContext context) {
        return new SftpResponseSpaceAvailableMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpResponseSpaceAvailableMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpResponseSpaceAvailableMessageHandler.SERIALIZER.serialize(this);
    }
}
