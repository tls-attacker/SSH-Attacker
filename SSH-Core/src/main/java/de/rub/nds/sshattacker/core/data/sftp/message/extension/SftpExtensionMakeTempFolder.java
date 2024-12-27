/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionMakeTempFolderHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionMakeTempFolder
        extends SftpExtensionWithVersion<SftpExtensionMakeTempFolder> {

    public SftpExtensionMakeTempFolder() {
        super();
    }

    public SftpExtensionMakeTempFolder(SftpExtensionMakeTempFolder other) {
        super(other);
    }

    @Override
    public SftpExtensionMakeTempFolder createCopy() {
        return new SftpExtensionMakeTempFolder(this);
    }

    @Override
    public SftpExtensionMakeTempFolderHandler getHandler(SshContext context) {
        return new SftpExtensionMakeTempFolderHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionMakeTempFolderHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionMakeTempFolderHandler.SERIALIZER.serialize(this);
    }
}
