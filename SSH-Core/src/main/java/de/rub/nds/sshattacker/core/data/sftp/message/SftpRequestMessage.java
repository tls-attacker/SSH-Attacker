/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessage;

public abstract class SftpRequestMessage<T extends SftpRequestMessage<T>> extends SftpMessage<T> {

    private ModifiableInteger requestId;

    public ModifiableInteger getRequestId() {
        return requestId;
    }

    public void setRequestId(ModifiableInteger requestId) {
        this.requestId = requestId;
    }

    public void setRequestId(int requestId) {
        this.requestId = ModifiableVariableFactory.safelySetValue(this.requestId, requestId);
    }
}
