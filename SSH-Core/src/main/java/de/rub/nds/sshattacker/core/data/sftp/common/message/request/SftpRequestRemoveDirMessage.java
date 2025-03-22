/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestRemoveDirMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestRemoveDirMessage
        extends SftpRequestWithPathMessage<SftpRequestRemoveDirMessage> {

    public SftpRequestRemoveDirMessage() {
        super();
    }

    public SftpRequestRemoveDirMessage(SftpRequestRemoveDirMessage other) {
        super(other);
    }

    @Override
    public SftpRequestRemoveDirMessage createCopy() {
        return new SftpRequestRemoveDirMessage(this);
    }

    public static final SftpRequestRemoveDirMessageHandler HANDLER =
            new SftpRequestRemoveDirMessageHandler();

    @Override
    public SftpRequestRemoveDirMessageHandler getHandler() {
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
        SftpRequestRemoveDirMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestRemoveDirMessageHandler.SERIALIZER.serialize(this);
    }
}
