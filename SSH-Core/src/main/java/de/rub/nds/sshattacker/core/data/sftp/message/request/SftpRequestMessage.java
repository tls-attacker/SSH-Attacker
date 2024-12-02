/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessage;

public abstract class SftpRequestMessage<T extends SftpRequestMessage<T>> extends SftpMessage<T> {

    private ModifiableInteger requestId;

    protected SftpRequestMessage() {
        super();
    }

    protected SftpRequestMessage(SftpRequestMessage<T> other) {
        super(other);
        requestId = other.requestId != null ? other.requestId.createCopy() : null;
    }

    public ModifiableInteger getRequestId() {
        return requestId;
    }

    public void setRequestId(ModifiableInteger requestId) {
        this.requestId = requestId;
    }

    public void setRequestId(int requestId) {
        this.requestId = ModifiableVariableFactory.safelySetValue(this.requestId, requestId);
    }

    public void setSoftlyRequestId(int requestId) {
        if (this.requestId == null || this.requestId.getOriginalValue() == null) {
            this.requestId = ModifiableVariableFactory.safelySetValue(this.requestId, requestId);
        }
    }
}
