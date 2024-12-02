/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestRemoveDirMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRemoveDirMessage
        extends SftpRequestWithPathMessage<SftpRequestRemoveDirMessage> {

    public SftpRequestRemoveDirMessage() {
        super();
    }

    public SftpRequestRemoveDirMessage(SftpRequestRemoveDirMessage other) {
        super(other);
    }

    @Override
    public SftpRequestRemoveDirMessage createCopy() {
        return new SftpRequestRemoveDirMessage(this);
    }

    @Override
    public SftpRequestRemoveDirMessageHandler getHandler(SshContext context) {
        return new SftpRequestRemoveDirMessageHandler(context, this);
    }
}
