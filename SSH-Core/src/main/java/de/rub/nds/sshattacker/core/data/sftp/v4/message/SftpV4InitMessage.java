/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.message;

import de.rub.nds.sshattacker.core.data.sftp.common.message.SftpHandshakeMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.handler.SftpV4InitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4InitMessage extends SftpHandshakeMessage<SftpV4InitMessage> {

    public SftpV4InitMessage() {
        super();
    }

    public SftpV4InitMessage(SftpV4InitMessage other) {
        super(other);
    }

    @Override
    public SftpV4InitMessage createCopy() {
        return new SftpV4InitMessage(this);
    }

    public static final SftpV4InitMessageHandler HANDLER = new SftpV4InitMessageHandler();

    @Override
    public SftpV4InitMessageHandler getHandler() {
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
        SftpV4InitMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpV4InitMessageHandler.SERIALIZER.serialize(this);
    }
}
