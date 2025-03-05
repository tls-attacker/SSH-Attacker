/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request.SftpRequestCopyDataMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlAttribute;

public class SftpRequestCopyDataMessage
        extends SftpRequestExtendedWithHandleMessage<SftpRequestCopyDataMessage> {

    // handle is the read from handle

    private ModifiableLong readFromOffset;
    private ModifiableLong readDataLength;
    private ModifiableInteger writeToHandleLength;
    private ModifiableByteArray writeToHandle;
    private ModifiableLong writeToOffset;

    @XmlAttribute(name = "writeToHandleIndex")
    private Integer configWriteToHandleIndex;

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
        configWriteToHandleIndex = other.configWriteToHandleIndex;
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

    public Integer getConfigWriteToHandleIndex() {
        return configWriteToHandleIndex;
    }

    public void setConfigWriteToHandleIndex(Integer configWriteToHandleIndex) {
        this.configWriteToHandleIndex = configWriteToHandleIndex;
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
