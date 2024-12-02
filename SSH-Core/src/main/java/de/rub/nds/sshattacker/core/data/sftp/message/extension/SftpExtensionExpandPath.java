/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionExpandPathHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionExpandPath extends SftpExtensionWithVersion<SftpExtensionExpandPath> {

    public SftpExtensionExpandPath() {
        super();
    }

    public SftpExtensionExpandPath(SftpExtensionExpandPath other) {
        super(other);
    }

    @Override
    public SftpExtensionExpandPath createCopy() {
        return new SftpExtensionExpandPath(this);
    }

    @Override
    public SftpExtensionExpandPathHandler getHandler(SshContext context) {
        return new SftpExtensionExpandPathHandler(context, this);
    }
}
