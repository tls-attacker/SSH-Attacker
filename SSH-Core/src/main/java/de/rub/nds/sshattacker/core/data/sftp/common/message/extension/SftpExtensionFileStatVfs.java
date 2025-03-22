/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.extension.SftpExtensionFileStatVfsHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionFileStatVfs extends SftpExtensionWithVersion<SftpExtensionFileStatVfs> {

    public SftpExtensionFileStatVfs() {
        super();
    }

    public SftpExtensionFileStatVfs(SftpExtensionFileStatVfs other) {
        super(other);
    }

    @Override
    public SftpExtensionFileStatVfs createCopy() {
        return new SftpExtensionFileStatVfs(this);
    }

    public static final SftpExtensionFileStatVfsHandler HANDLER =
            new SftpExtensionFileStatVfsHandler();

    @Override
    public SftpExtensionFileStatVfsHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionFileStatVfsHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionFileStatVfsHandler.SERIALIZER.serialize(this);
    }
}
