/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestGetTempFolderMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestGetTempFolderMessage
        extends SftpRequestExtendedMessage<SftpRequestGetTempFolderMessage> {

    public SftpRequestGetTempFolderMessage() {
        super();
    }

    public SftpRequestGetTempFolderMessage(SftpRequestGetTempFolderMessage other) {
        super(other);
    }

    @Override
    public SftpRequestGetTempFolderMessage createCopy() {
        return new SftpRequestGetTempFolderMessage(this);
    }

    @Override
    public SftpRequestGetTempFolderMessageHandler getHandler(SshContext context) {
        return new SftpRequestGetTempFolderMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestGetTempFolderMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
