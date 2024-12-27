/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestMakeTempFolderMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestMakeTempFolderMessage
        extends SftpRequestExtendedMessage<SftpRequestMakeTempFolderMessage> {

    public SftpRequestMakeTempFolderMessage() {
        super();
    }

    public SftpRequestMakeTempFolderMessage(SftpRequestMakeTempFolderMessage other) {
        super(other);
    }

    @Override
    public SftpRequestMakeTempFolderMessage createCopy() {
        return new SftpRequestMakeTempFolderMessage(this);
    }

    @Override
    public SftpRequestMakeTempFolderMessageHandler getHandler(SshContext context) {
        return new SftpRequestMakeTempFolderMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestMakeTempFolderMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestMakeTempFolderMessageHandler.SERIALIZER.serialize(this);
    }
}
