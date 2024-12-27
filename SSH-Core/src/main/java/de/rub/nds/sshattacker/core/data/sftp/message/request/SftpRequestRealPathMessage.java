/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestRealPathMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestRealPathMessage
        extends SftpRequestWithPathMessage<SftpRequestRealPathMessage> {

    public SftpRequestRealPathMessage() {
        super();
    }

    public SftpRequestRealPathMessage(SftpRequestRealPathMessage other) {
        super(other);
    }

    @Override
    public SftpRequestRealPathMessage createCopy() {
        return new SftpRequestRealPathMessage(this);
    }

    @Override
    public SftpRequestRealPathMessageHandler getHandler(SshContext context) {
        return new SftpRequestRealPathMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestRealPathMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
