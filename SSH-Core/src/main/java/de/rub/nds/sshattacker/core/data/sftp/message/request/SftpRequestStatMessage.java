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
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestStatMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestStatMessage extends SftpRequestWithPathMessage<SftpRequestStatMessage> {

    private ModifiableInteger flags;

    public ModifiableInteger getFlags() {
        return flags;
    }

    public void setFlags(ModifiableInteger flags) {
        this.flags = flags;
    }

    public void setFlags(int flags) {
        this.flags = ModifiableVariableFactory.safelySetValue(this.flags, flags);
    }

    public void setFlags(SftpFileAttributeFlag... flags) {
        setFlags(SftpFileAttributeFlag.flagsToInt(flags));
    }

    public void clearFlags() {
        flags = null;
    }

    @Override
    public SftpRequestStatMessageHandler getHandler(SshContext context) {
        return new SftpRequestStatMessageHandler(context, this);
    }
}
