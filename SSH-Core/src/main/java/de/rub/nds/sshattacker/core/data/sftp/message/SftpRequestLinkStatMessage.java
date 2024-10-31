/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message;

import de.rub.nds.sshattacker.core.data.sftp.handler.SftpRequestLinkStatMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestLinkStatMessage
        extends SftpRequestWithPathMessage<SftpRequestLinkStatMessage> {

    @Override
    public SftpRequestLinkStatMessageHandler getHandler(SshContext context) {
        return new SftpRequestLinkStatMessageHandler(context, this);
    }
}
