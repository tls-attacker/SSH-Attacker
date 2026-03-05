/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestReadDirMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestReadDirMessage
        extends SftpRequestWithHandleMessage<SftpRequestReadDirMessage> {

    public SftpRequestReadDirMessage() {
        super();
    }

    public SftpRequestReadDirMessage(int handleIndex) {
        super();
        configHandleIndex = handleIndex;
    }

    public SftpRequestReadDirMessage(SftpRequestReadDirMessage other) {
        super(other);
    }

    @Override
    public SftpRequestReadDirMessage createCopy() {
        return new SftpRequestReadDirMessage(this);
    }

    public static final SftpRequestReadDirMessageHandler HANDLER =
            new SftpRequestReadDirMessageHandler();

    @Override
    public SftpRequestReadDirMessageHandler getHandler() {
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
        SftpRequestReadDirMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestReadDirMessageHandler.SERIALIZER.serialize(this);
    }
}
