/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.SftpFileOpenFlag;
import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestOpenMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.List;

public class SftpRequestOpenMessage extends SftpRequestWithPathMessage<SftpRequestOpenMessage> {

    // path is the filename

    private ModifiableInteger pFlags;

    @HoldsModifiableVariable private SftpFileAttributes attributes;

    public ModifiableInteger getPFlags() {
        return pFlags;
    }

    public void setPFlags(ModifiableInteger pFlags) {
        this.pFlags = pFlags;
    }

    public void setPFlags(int pFlags) {
        this.pFlags = ModifiableVariableFactory.safelySetValue(this.pFlags, pFlags);
    }

    public void setPFlags(SftpFileOpenFlag... fileOpenFlags) {
        setPFlags(SftpFileOpenFlag.flagsToInt(fileOpenFlags));
    }

    public SftpFileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpFileAttributes attributes) {
        this.attributes = attributes;
    }

    @Override
    public SftpRequestOpenMessageHandler getHandler(SshContext context) {
        return new SftpRequestOpenMessageHandler(context, this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (attributes != null) {
            holders.addAll(attributes.getAllModifiableVariableHolders());
        }
        return holders;
    }
}
