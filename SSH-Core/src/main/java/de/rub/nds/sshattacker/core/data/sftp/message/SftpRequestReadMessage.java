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
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.data.sftp.handler.SftpRequestReadMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestReadMessage extends SftpRequestWithHandleMessage<SftpRequestReadMessage> {

    private ModifiableLong offset;
    private ModifiableInteger length;

    public ModifiableLong getOffset() {
        return offset;
    }

    public void setOffset(ModifiableLong offset) {
        this.offset = offset;
    }

    public void setOffset(long offset) {
        this.offset = ModifiableVariableFactory.safelySetValue(this.offset, offset);
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    @Override
    public SftpRequestReadMessageHandler getHandler(SshContext context) {
        return new SftpRequestReadMessageHandler(context, this);
    }
}
