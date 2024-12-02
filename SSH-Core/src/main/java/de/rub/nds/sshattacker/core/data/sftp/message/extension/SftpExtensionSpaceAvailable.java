/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionSpaceAvailableHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionSpaceAvailable
        extends SftpExtensionWithVersion<SftpExtensionSpaceAvailable> {

    public SftpExtensionSpaceAvailable() {
        super();
    }

    public SftpExtensionSpaceAvailable(SftpExtensionSpaceAvailable other) {
        super(other);
    }

    @Override
    public SftpExtensionSpaceAvailable createCopy() {
        return new SftpExtensionSpaceAvailable(this);
    }

    @Override
    public SftpExtensionSpaceAvailableHandler getHandler(SshContext context) {
        return new SftpExtensionSpaceAvailableHandler(context, this);
    }
}
