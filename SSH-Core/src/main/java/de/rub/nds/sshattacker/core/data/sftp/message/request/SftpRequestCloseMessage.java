/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestCloseMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestCloseMessage extends SftpRequestWithHandleMessage<SftpRequestCloseMessage> {

    public SftpRequestCloseMessage() {
        super();
    }

    public SftpRequestCloseMessage(SftpRequestCloseMessage other) {
        super(other);
    }

    @Override
    public SftpRequestCloseMessage createCopy() {
        return new SftpRequestCloseMessage(this);
    }

    public static final SftpRequestCloseMessageHandler HANDLER =
            new SftpRequestCloseMessageHandler();

    @Override
    public SftpRequestCloseMessageHandler getHandler() {
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
        SftpRequestCloseMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestCloseMessageHandler.SERIALIZER.serialize(this);
    }
}
