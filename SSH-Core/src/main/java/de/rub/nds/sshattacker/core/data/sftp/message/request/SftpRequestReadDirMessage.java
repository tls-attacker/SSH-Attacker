/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestReadDirMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestReadDirMessage
        extends SftpRequestWithHandleMessage<SftpRequestReadDirMessage> {

    public SftpRequestReadDirMessage() {
        super();
    }

    public SftpRequestReadDirMessage(SftpRequestReadDirMessage other) {
        super(other);
    }

    @Override
    public SftpRequestReadDirMessage createCopy() {
        return new SftpRequestReadDirMessage(this);
    }

    @Override
    public SftpRequestReadDirMessageHandler getHandler(SshContext context) {
        return new SftpRequestReadDirMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestReadDirMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
