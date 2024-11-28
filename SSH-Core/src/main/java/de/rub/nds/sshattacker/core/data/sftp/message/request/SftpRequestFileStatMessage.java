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
import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestFileStatMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileStatMessage
        extends SftpRequestWithHandleMessage<SftpRequestFileStatMessage> {

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

    public void setSoftlyFlags(int flags) {
        if (this.flags == null || this.flags.getOriginalValue() == null) {
            this.flags = ModifiableVariableFactory.safelySetValue(this.flags, flags);
        }
    }

    public void setFlags(SftpFileAttributeFlag... flags) {
        setFlags(SftpFileAttributeFlag.flagsToInt(flags));
    }

    public void setSoftlyFlags(SftpFileAttributeFlag... flags) {
        setSoftlyFlags(SftpFileAttributeFlag.flagsToInt(flags));
    }

    public void clearFlags() {
        flags = null;
    }

    @Override
    public SftpRequestFileStatMessageHandler getHandler(SshContext context) {
        return new SftpRequestFileStatMessageHandler(context, this);
    }
}
