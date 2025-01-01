/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestRemoveMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestRemoveMessage extends SftpRequestWithPathMessage<SftpRequestRemoveMessage> {

    // path is the filename

    public SftpRequestRemoveMessage() {
        super();
    }

    public SftpRequestRemoveMessage(SftpRequestRemoveMessage other) {
        super(other);
    }

    @Override
    public SftpRequestRemoveMessage createCopy() {
        return new SftpRequestRemoveMessage(this);
    }

    public static final SftpRequestRemoveMessageHandler HANDLER =
            new SftpRequestRemoveMessageHandler();

    @Override
    public SftpRequestRemoveMessageHandler getHandler() {
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
        SftpRequestRemoveMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestRemoveMessageHandler.SERIALIZER.serialize(this);
    }
}
