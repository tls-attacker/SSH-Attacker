/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMakeDirMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.List;

public class SftpRequestMakeDirMessage
        extends SftpRequestWithPathMessage<SftpRequestMakeDirMessage> {

    @HoldsModifiableVariable private SftpFileAttributes attributes;

    public SftpFileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpFileAttributes attributes) {
        this.attributes = attributes;
    }

    @Override
    public SftpRequestMakeDirMessageHandler getHandler(SshContext context) {
        return new SftpRequestMakeDirMessageHandler(context, this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        holders.addAll(attributes.getAllModifiableVariableHolders());
        return holders;
    }
}
