/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionFileStatVfsHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionFileStatVfs extends SftpExtensionWithVersion<SftpExtensionFileStatVfs> {

    public SftpExtensionFileStatVfs() {
        super();
    }

    public SftpExtensionFileStatVfs(SftpExtensionFileStatVfs other) {
        super(other);
    }

    @Override
    public SftpExtensionFileStatVfs createCopy() {
        return new SftpExtensionFileStatVfs(this);
    }

    @Override
    public SftpExtensionFileStatVfsHandler getHandler(SshContext context) {
        return new SftpExtensionFileStatVfsHandler(context, this);
    }
}
