/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestOpenDirMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestOpenDirMessage
        extends SftpRequestWithPathMessage<SftpRequestOpenDirMessage> {

    public SftpRequestOpenDirMessage() {
        super();
    }

    public SftpRequestOpenDirMessage(SftpRequestOpenDirMessage other) {
        super(other);
    }

    @Override
    public SftpRequestOpenDirMessage createCopy() {
        return new SftpRequestOpenDirMessage(this);
    }

    public static final SftpRequestOpenDirMessageHandler HANDLER =
            new SftpRequestOpenDirMessageHandler();

    @Override
    public SftpRequestOpenDirMessageHandler getHandler() {
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
        SftpRequestOpenDirMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestOpenDirMessageHandler.SERIALIZER.serialize(this);
    }
}
