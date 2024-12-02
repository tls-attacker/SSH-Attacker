/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessage;

public abstract class SftpResponseMessage<T extends SftpResponseMessage<T>> extends SftpMessage<T> {

    private ModifiableInteger requestId;

    protected SftpResponseMessage() {
        super();
    }

    protected SftpResponseMessage(SftpResponseMessage<T> other) {
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
