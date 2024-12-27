/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestFileStatVfsMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestFileStatVfsMessage
        extends SftpRequestExtendedWithHandleMessage<SftpRequestFileStatVfsMessage> {

    public SftpRequestFileStatVfsMessage() {
        super();
    }

    public SftpRequestFileStatVfsMessage(SftpRequestFileStatVfsMessage other) {
        super(other);
    }

    @Override
    public SftpRequestFileStatVfsMessage createCopy() {
        return new SftpRequestFileStatVfsMessage(this);
    }

    @Override
    public SftpRequestFileStatVfsMessageHandler getHandler(SshContext context) {
        return new SftpRequestFileStatVfsMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestFileStatVfsMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestFileStatVfsMessageHandler.SERIALIZER.serialize(this);
    }
}
