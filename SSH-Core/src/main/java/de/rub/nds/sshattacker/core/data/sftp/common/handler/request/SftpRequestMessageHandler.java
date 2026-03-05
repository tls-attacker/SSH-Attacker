/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public abstract class SftpRequestMessageHandler<T extends SftpRequestMessage<T>>
        extends SftpMessageHandler<T> implements MessageSentHandler<T> {

    @Override
    public void adjustContext(SshContext context, T object) {
        context.getSftpManager().handleRequestMessage(object);
    }

    @Override
    public void adjustContextAfterMessageSent(SshContext context, T object) {
        context.getSftpManager().addRequest(object);
    }
}
