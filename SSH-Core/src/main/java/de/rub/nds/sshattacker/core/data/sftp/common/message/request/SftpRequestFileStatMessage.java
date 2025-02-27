/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestFileStatMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestFileStatMessage
        extends SftpRequestWithHandleMessage<SftpRequestFileStatMessage> {

    public SftpRequestFileStatMessage() {
        super();
    }

    public SftpRequestFileStatMessage(SftpRequestFileStatMessage other) {
        super(other);
    }

    @Override
    public SftpRequestFileStatMessage createCopy() {
        return new SftpRequestFileStatMessage(this);
    }

    public static final SftpRequestFileStatMessageHandler HANDLER =
            new SftpRequestFileStatMessageHandler();

    @Override
    public SftpRequestFileStatMessageHandler getHandler() {
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
        SftpRequestFileStatMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestFileStatMessageHandler.SERIALIZER.serialize(this);
    }
}
