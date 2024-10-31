/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message;

import de.rub.nds.sshattacker.core.data.sftp.handler.SftpRequestCloseMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCloseMessage extends SftpRequestWithHandleMessage<SftpRequestCloseMessage> {

    @Override
    public SftpRequestCloseMessageHandler getHandler(SshContext context) {
        return new SftpRequestCloseMessageHandler(context, this);
    }
}
