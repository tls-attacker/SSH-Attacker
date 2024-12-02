/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionUsersGroupsByIdHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionUsersGroupsById
        extends SftpExtensionWithVersion<SftpExtensionUsersGroupsById> {

    public SftpExtensionUsersGroupsById() {
        super();
    }

    public SftpExtensionUsersGroupsById(SftpExtensionUsersGroupsById other) {
        super(other);
    }

    @Override
    public SftpExtensionUsersGroupsById createCopy() {
        return new SftpExtensionUsersGroupsById(this);
    }

    @Override
    public SftpExtensionUsersGroupsByIdHandler getHandler(SshContext context) {
        return new SftpExtensionUsersGroupsByIdHandler(context, this);
    }
}
