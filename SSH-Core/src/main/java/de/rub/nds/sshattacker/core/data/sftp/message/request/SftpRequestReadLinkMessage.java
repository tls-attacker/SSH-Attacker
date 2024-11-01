/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestReadLinkMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestReadLinkMessage
        extends SftpRequestWithPathMessage<SftpRequestReadLinkMessage> {

    @Override
    public SftpRequestReadLinkMessageHandler getHandler(SshContext context) {
        return new SftpRequestReadLinkMessageHandler(context, this);
    }
}
