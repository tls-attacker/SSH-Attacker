/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestReadLinkMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestReadLinkMessage
        extends SftpRequestWithPathMessage<SftpRequestReadLinkMessage> {

    public SftpRequestReadLinkMessage() {
        super();
    }

    public SftpRequestReadLinkMessage(SftpRequestReadLinkMessage other) {
        super(other);
    }

    @Override
    public SftpRequestReadLinkMessage createCopy() {
        return new SftpRequestReadLinkMessage(this);
    }

    public static final SftpRequestReadLinkMessageHandler HANDLER =
            new SftpRequestReadLinkMessageHandler();

    @Override
    public SftpRequestReadLinkMessageHandler getHandler() {
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
        SftpRequestReadLinkMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestReadLinkMessageHandler.SERIALIZER.serialize(this);
    }
}
