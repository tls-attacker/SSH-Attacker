/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestStatVfsMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestStatVfsMessage
        extends SftpRequestExtendedWithPathMessage<SftpRequestStatVfsMessage> {

    public SftpRequestStatVfsMessage() {
        super();
    }

    public SftpRequestStatVfsMessage(SftpRequestStatVfsMessage other) {
        super(other);
    }

    @Override
    public SftpRequestStatVfsMessage createCopy() {
        return new SftpRequestStatVfsMessage(this);
    }

    public static final SftpRequestStatVfsMessageHandler HANDLER =
            new SftpRequestStatVfsMessageHandler();

    @Override
    public SftpRequestStatVfsMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestStatVfsMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestStatVfsMessageHandler.SERIALIZER.serialize(this);
    }
}
