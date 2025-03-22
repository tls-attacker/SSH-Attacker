/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.extension.SftpExtensionCopyFileHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionCopyFile extends SftpExtensionWithVersion<SftpExtensionCopyFile> {

    public SftpExtensionCopyFile() {
        super();
    }

    public SftpExtensionCopyFile(SftpExtensionCopyFile other) {
        super(other);
    }

    @Override
    public SftpExtensionCopyFile createCopy() {
        return new SftpExtensionCopyFile(this);
    }

    public static final SftpExtensionCopyFileHandler HANDLER = new SftpExtensionCopyFileHandler();

    @Override
    public SftpExtensionCopyFileHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionCopyFileHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionCopyFileHandler.SERIALIZER.serialize(this);
    }
}
