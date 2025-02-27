/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.SftpVersionMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpVersionMessage extends SftpHandshakeMessage<SftpVersionMessage> {

    public SftpVersionMessage() {
        super();
    }

    public SftpVersionMessage(SftpVersionMessage other) {
        super(other);
    }

    @Override
    public SftpVersionMessage createCopy() {
        return new SftpVersionMessage(this);
    }

    public static final SftpVersionMessageHandler HANDLER = new SftpVersionMessageHandler();

    @Override
    public SftpVersionMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpVersionMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpVersionMessageHandler.SERIALIZER.serialize(this);
    }
}
