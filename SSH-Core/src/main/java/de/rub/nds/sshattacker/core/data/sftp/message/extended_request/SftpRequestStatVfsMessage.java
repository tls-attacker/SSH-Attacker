/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestStatVfsMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestStatVfsMessage
        extends SftpRequestExtendedWithPathMessage<SftpRequestStatVfsMessage> {

    @Override
    public SftpRequestStatVfsMessageHandler getHandler(SshContext context) {
        return new SftpRequestStatVfsMessageHandler(context);
    }
}
