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
import de.rub.nds.sshattacker.core.config.Config;

public abstract class SftpRequestExtendedWithHandleMessage<
                T extends SftpRequestExtendedWithHandleMessage<T>>
        extends SftpRequestExtendedMessage<T> {

    private ModifiableInteger handleLength;
    private ModifiableByteArray handle;

    protected SftpRequestExtendedWithHandleMessage() {
        super();
    }

    protected SftpRequestExtendedWithHandleMessage(SftpRequestExtendedWithHandleMessage<T> other) {
        super(other);
        handleLength = other.handleLength != null ? other.handleLength.createCopy() : null;
        handle = other.handle != null ? other.handle.createCopy() : null;
    }

    @Override
    public abstract SftpRequestExtendedWithHandleMessage<T> createCopy();

    public ModifiableInteger getHandleLength() {
        return handleLength;
    }

    public void setHandleLength(ModifiableInteger handleLength) {
        this.handleLength = handleLength;
    }

    public void setHandleLength(int handleLength) {
        this.handleLength =
                ModifiableVariableFactory.safelySetValue(this.handleLength, handleLength);
    }

    public ModifiableByteArray getHandle() {
        return handle;
    }

    public void setHandle(ModifiableByteArray handle) {
        setHandle(handle, false);
    }

    public void setHandle(byte[] handle) {
        setHandle(handle, false);
    }

    public void setHandle(ModifiableByteArray handle, boolean adjustLengthField) {
        this.handle = handle;
        if (adjustLengthField) {
            setHandleLength(this.handle.getValue().length);
        }
    }

    public void setHandle(byte[] handle, boolean adjustLengthField) {
        this.handle = ModifiableVariableFactory.safelySetValue(this.handle, handle);
        if (adjustLengthField) {
            setHandleLength(this.handle.getValue().length);
        }
    }

    public void setSoftlyHandle(byte[] handle, boolean adjustLengthField, Config config) {
        this.handle =
                ModifiableVariableFactory.softlySetValue(
                        this.handle, handle, config.getAlwaysPrepareSftpHandle());
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || handleLength == null
                    || handleLength.getOriginalValue() == null) {
                setHandleLength(this.handle.getValue().length);
            }
        }
    }
}
