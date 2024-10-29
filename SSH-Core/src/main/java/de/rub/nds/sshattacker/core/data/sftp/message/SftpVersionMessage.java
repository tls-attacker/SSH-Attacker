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
import de.rub.nds.sshattacker.core.data.sftp.handler.SftpVersionMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpVersionMessage extends SftpMessage<SftpVersionMessage> {

    private ModifiableInteger version;

    public ModifiableInteger getVersion() {
        return version;
    }

    public void setVersion(ModifiableInteger version) {
        this.version = version;
    }

    public void setVersion(Integer version) {
        this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
    }

    @Override
    public SftpVersionMessageHandler getHandler(SshContext context) {
        return new SftpVersionMessageHandler(context, this);
    }
}
