/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.response.SftpResponseHandleMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseHandleMessage extends SftpResponseMessage<SftpResponseHandleMessage> {

    private ModifiableInteger handleLength;
    private ModifiableByteArray handle;

    public SftpResponseHandleMessage() {
        super();
    }

    public SftpResponseHandleMessage(SftpResponseHandleMessage other) {
        super(other);
        handleLength = other.handleLength != null ? other.handleLength.createCopy() : null;
        handle = other.handle != null ? other.handle.createCopy() : null;
    }

    @Override
    public SftpResponseHandleMessage createCopy() {
        return new SftpResponseHandleMessage(this);
    }

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

    public void setSoftlyHandleLength(int handleLength, Config config) {
        if (config.getAlwaysPrepareSftpLengthFields()
                || this.handleLength == null
                || this.handleLength.getOriginalValue() == null) {
            this.handleLength =
                    ModifiableVariableFactory.safelySetValue(this.handleLength, handleLength);
        }
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
        if (config.getAlwaysPrepareSftpHandle()
                || this.handle == null
                || this.handle.getOriginalValue() == null) {
            this.handle = ModifiableVariableFactory.safelySetValue(this.handle, handle);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || handleLength == null
                    || handleLength.getOriginalValue() == null) {
                setHandleLength(this.handle.getValue().length);
            }
        }
    }

    @Override
    public SftpResponseHandleMessageHandler getHandler(SshContext context) {
        return new SftpResponseHandleMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpResponseHandleMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
