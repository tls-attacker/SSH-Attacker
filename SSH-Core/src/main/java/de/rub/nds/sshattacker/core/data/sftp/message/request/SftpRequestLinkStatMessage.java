/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestLinkStatMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestLinkStatMessage
        extends SftpRequestWithPathMessage<SftpRequestLinkStatMessage> {

    public SftpRequestLinkStatMessage() {
        super();
    }

    public SftpRequestLinkStatMessage(SftpRequestLinkStatMessage other) {
        super(other);
    }

    @Override
    public SftpRequestLinkStatMessage createCopy() {
        return new SftpRequestLinkStatMessage(this);
    }

    public static final SftpRequestLinkStatMessageHandler HANDLER =
            new SftpRequestLinkStatMessageHandler();

    @Override
    public SftpRequestLinkStatMessageHandler getHandler() {
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
        SftpRequestLinkStatMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestLinkStatMessageHandler.SERIALIZER.serialize(this);
    }
}
