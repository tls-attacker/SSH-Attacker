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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestStatMessage extends SftpRequestWithPathMessage<SftpRequestStatMessage> {

    private ModifiableInteger flags;

    public SftpRequestStatMessage() {
        super();
    }

    public SftpRequestStatMessage(SftpRequestStatMessage other) {
        super(other);
        flags = other.flags != null ? other.flags.createCopy() : null;
    }

    @Override
    public SftpRequestStatMessage createCopy() {
        return new SftpRequestStatMessage(this);
    }

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
    public SftpRequestStatMessageHandler getHandler(SshContext context) {
        return new SftpRequestStatMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestStatMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestStatMessageHandler.SERIALIZER.serialize(this);
    }
}
