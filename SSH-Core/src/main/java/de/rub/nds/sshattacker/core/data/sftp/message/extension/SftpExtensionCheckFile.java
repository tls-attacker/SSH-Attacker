/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionCheckFileHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionCheckFile extends SftpExtensionWithVersion<SftpExtensionCheckFile> {

    public SftpExtensionCheckFile() {
        super();
    }

    public SftpExtensionCheckFile(SftpExtensionCheckFile other) {
        super(other);
    }

    @Override
    public SftpExtensionCheckFile createCopy() {
        return new SftpExtensionCheckFile(this);
    }

    public static final SftpExtensionCheckFileHandler HANDLER = new SftpExtensionCheckFileHandler();

    @Override
    public SftpExtensionCheckFileHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionCheckFileHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionCheckFileHandler.SERIALIZER.serialize(this);
    }
}
