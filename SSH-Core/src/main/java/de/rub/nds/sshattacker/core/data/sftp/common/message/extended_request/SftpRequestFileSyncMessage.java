/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request.SftpRequestFileSyncMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestFileSyncMessage
        extends SftpRequestExtendedWithHandleMessage<SftpRequestFileSyncMessage> {

    public SftpRequestFileSyncMessage() {
        super();
    }

    public SftpRequestFileSyncMessage(int handleIndex) {
        super();
        configHandleIndex = handleIndex;
    }

    public SftpRequestFileSyncMessage(SftpRequestFileSyncMessage other) {
        super(other);
    }

    @Override
    public SftpRequestFileSyncMessage createCopy() {
        return new SftpRequestFileSyncMessage(this);
    }

    public static final SftpRequestFileSyncMessageHandler HANDLER =
            new SftpRequestFileSyncMessageHandler();

    @Override
    public SftpRequestFileSyncMessageHandler getHandler() {
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
        SftpRequestFileSyncMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestFileSyncMessageHandler.SERIALIZER.serialize(this);
    }
}
