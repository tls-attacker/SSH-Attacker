/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message;

import de.rub.nds.sshattacker.core.data.sftp.handler.SftpRequestRemoveMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRemoveMessage extends SftpRequestWithPathMessage<SftpRequestRemoveMessage> {

    // path is the filename

    @Override
    public SftpRequestRemoveMessageHandler getHandler(SshContext context) {
        return new SftpRequestRemoveMessageHandler(context, this);
    }
}
