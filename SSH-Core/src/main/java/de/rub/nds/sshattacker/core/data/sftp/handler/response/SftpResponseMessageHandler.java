/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public abstract class SftpResponseMessageHandler<T extends SftpResponseMessage<T>>
        extends SftpMessageHandler<T> {

    @Override
    public void adjustContext(SshContext context, T object) {
        context.getSftpManager().removeRequestById(object.getRequestId().getValue());
    }
}
