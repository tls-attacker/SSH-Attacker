/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestCopyDataMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestCopyDataMessage
        extends SftpRequestExtendedWithHandleMessage<SftpRequestCopyDataMessage> {

    // handle is the read from handle

    private ModifiableLong readFromOffset;
    private ModifiableLong readDataLength;
    private ModifiableInteger writeToHandleLength;
    private ModifiableByteArray writeToHandle;
    private ModifiableLong writeToOffset;

    public SftpRequestCopyDataMessage() {
        super();
    }

    public SftpRequestCopyDataMessage(SftpRequestCopyDataMessage other) {
        super(other);
        readFromOffset = other.readFromOffset != null ? other.readFromOffset.createCopy() : null;
        readDataLength = other.readDataLength != null ? other.readDataLength.createCopy() : null;
        writeToHandleLength =
                other.writeToHandleLength != null ? other.writeToHandleLength.createCopy() : null;
        writeToHandle = other.writeToHandle != null ? other.writeToHandle.createCopy() : null;
        writeToOffset = other.writeToOffset != null ? other.writeToOffset.createCopy() : null;
    }

    @Override
    public SftpRequestCopyDataMessage createCopy() {
        return new SftpRequestCopyDataMessage(this);
    }

    public ModifiableLong getReadFromOffset() {
        return readFromOffset;
    }

    public void setReadFromOffset(ModifiableLong readFromOffset) {
        this.readFromOffset = readFromOffset;
    }

    public void setReadFromOffset(long readFromOffset) {
        this.readFromOffset =
                ModifiableVariableFactory.safelySetValue(this.readFromOffset, readFromOffset);
    }

    public void setSoftlyReadFromOffset(long readFromOffset) {
        if (this.readFromOffset == null || this.readFromOffset.getOriginalValue() == null) {
            this.readFromOffset =
                    ModifiableVariableFactory.safelySetValue(this.readFromOffset, readFromOffset);
        }
    }

    public ModifiableLong getReadDataLength() {
        return readDataLength;
    }

    public void setReadDataLength(ModifiableLong readDataLength) {
        this.readDataLength = readDataLength;
    }

    public void setReadDataLength(long readDataLength) {
        this.readDataLength =
                ModifiableVariableFactory.safelySetValue(this.readDataLength, readDataLength);
    }

    public void setSoftlyReadDataLength(long readDataLength) {
        if (this.readDataLength == null || this.readDataLength.getOriginalValue() == null) {
            this.readDataLength =
                    ModifiableVariableFactory.safelySetValue(this.readDataLength, readDataLength);
        }
    }

    public ModifiableInteger getWriteToHandleLength() {
        return writeToHandleLength;
    }

    public void setWriteToHandleLength(ModifiableInteger writeToHandleLength) {
        this.writeToHandleLength = writeToHandleLength;
    }

    public void setWriteToHandleLength(int writeToHandleLength) {
        this.writeToHandleLength =
                ModifiableVariableFactory.safelySetValue(
                        this.writeToHandleLength, writeToHandleLength);
    }

    public ModifiableByteArray getWriteToHandle() {
        return writeToHandle;
    }

    public void setWriteToHandle(ModifiableByteArray writeToHandle) {
        setWriteToHandle(writeToHandle, false);
    }

    public void setWriteToHandle(byte[] writeToHandle) {
        setWriteToHandle(writeToHandle, false);
    }

    public void setWriteToHandle(ModifiableByteArray writeToHandle, boolean adjustLengthField) {
        this.writeToHandle = writeToHandle;
        if (adjustLengthField) {
            setWriteToHandleLength(this.writeToHandle.getValue().length);
        }
    }

    public void setWriteToHandle(byte[] writeToHandle, boolean adjustLengthField) {
        this.writeToHandle =
                ModifiableVariableFactory.safelySetValue(this.writeToHandle, writeToHandle);
        if (adjustLengthField) {
            setWriteToHandleLength(this.writeToHandle.getValue().length);
        }
    }

    public void setSoftlyWriteToHandle(
            byte[] writeToHandle, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareSftpHandle()
                || this.writeToHandle == null
                || this.writeToHandle.getOriginalValue() == null) {
            this.writeToHandle =
                    ModifiableVariableFactory.safelySetValue(this.writeToHandle, writeToHandle);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || writeToHandleLength == null
                    || writeToHandleLength.getOriginalValue() == null) {
                setWriteToHandleLength(this.writeToHandle.getValue().length);
            }
        }
    }

    public ModifiableLong getWriteToOffset() {
        return writeToOffset;
    }

    public void setWriteToOffset(ModifiableLong writeToOffset) {
        this.writeToOffset = writeToOffset;
    }

    public void setWriteToOffset(long writeToOffset) {
        this.writeToOffset =
                ModifiableVariableFactory.safelySetValue(this.writeToOffset, writeToOffset);
    }

    public void setSoftlyWriteToOffset(long writeToOffset) {
        if (this.writeToOffset == null || this.writeToOffset.getOriginalValue() == null) {
            this.writeToOffset =
                    ModifiableVariableFactory.safelySetValue(this.writeToOffset, writeToOffset);
        }
    }

    public static final SftpRequestCopyDataMessageHandler HANDLER =
            new SftpRequestCopyDataMessageHandler();

    @Override
    public SftpRequestCopyDataMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestCopyDataMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestCopyDataMessageHandler.SERIALIZER.serialize(this);
    }
}
