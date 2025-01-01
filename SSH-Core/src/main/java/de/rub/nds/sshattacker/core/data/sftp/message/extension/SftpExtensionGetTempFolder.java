/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionGetTempFolderHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionGetTempFolder
        extends SftpExtensionWithVersion<SftpExtensionGetTempFolder> {

    public SftpExtensionGetTempFolder() {
        super();
    }

    public SftpExtensionGetTempFolder(SftpExtensionGetTempFolder other) {
        super(other);
    }

    @Override
    public SftpExtensionGetTempFolder createCopy() {
        return new SftpExtensionGetTempFolder(this);
    }

    public static final SftpExtensionGetTempFolderHandler HANDLER =
            new SftpExtensionGetTempFolderHandler();

    @Override
    public SftpExtensionGetTempFolderHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionGetTempFolderHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionGetTempFolderHandler.SERIALIZER.serialize(this);
    }
}
