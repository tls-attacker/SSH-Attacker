/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

public abstract class SftpRequestWithHandleMessage<T extends SftpRequestWithHandleMessage<T>>
        extends SftpRequestMessage<T> {

    private ModifiableByteArray handle;
    private ModifiableInteger handleLength;

    protected SftpRequestWithHandleMessage() {
        super();
    }

    protected SftpRequestWithHandleMessage(SftpRequestWithHandleMessage<T> other) {
        super(other);
        handle = other.handle != null ? other.handle.createCopy() : null;
        handleLength = other.handleLength != null ? other.handleLength.createCopy() : null;
    }

    @Override
    public abstract SftpRequestWithHandleMessage<T> createCopy();

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
}
