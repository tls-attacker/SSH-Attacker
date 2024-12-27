/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestSpaceAvailableMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestSpaceAvailableMessage
        extends SftpRequestExtendedWithPathMessage<SftpRequestSpaceAvailableMessage> {

    public SftpRequestSpaceAvailableMessage() {
        super();
    }

    public SftpRequestSpaceAvailableMessage(SftpRequestSpaceAvailableMessage other) {
        super(other);
    }

    @Override
    public SftpRequestSpaceAvailableMessage createCopy() {
        return new SftpRequestSpaceAvailableMessage(this);
    }

    @Override
    public SftpRequestSpaceAvailableMessageHandler getHandler(SshContext context) {
        return new SftpRequestSpaceAvailableMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestSpaceAvailableMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
