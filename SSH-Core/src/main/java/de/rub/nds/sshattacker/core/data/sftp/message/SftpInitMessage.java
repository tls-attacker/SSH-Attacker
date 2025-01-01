/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message;

import de.rub.nds.sshattacker.core.data.sftp.handler.SftpInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpInitMessage extends SftpHandshakeMessage<SftpInitMessage> {

    public SftpInitMessage() {
        super();
    }

    public SftpInitMessage(SftpInitMessage other) {
        super(other);
    }

    @Override
    public SftpInitMessage createCopy() {
        return new SftpInitMessage(this);
    }

    public static final SftpInitMessageHandler HANDLER = new SftpInitMessageHandler();

    @Override
    public SftpInitMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpInitMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpInitMessageHandler.SERIALIZER.serialize(this);
    }
}
