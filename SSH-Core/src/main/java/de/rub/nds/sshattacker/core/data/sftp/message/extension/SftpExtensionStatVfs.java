/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionStatVfsHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionStatVfs extends SftpExtensionWithVersion<SftpExtensionStatVfs> {

    public SftpExtensionStatVfs() {
        super();
    }

    public SftpExtensionStatVfs(SftpExtensionStatVfs other) {
        super(other);
    }

    @Override
    public SftpExtensionStatVfs createCopy() {
        return new SftpExtensionStatVfs(this);
    }

    @Override
    public SftpExtensionStatVfsHandler getHandler(SshContext context) {
        return new SftpExtensionStatVfsHandler(context, this);
    }
}
