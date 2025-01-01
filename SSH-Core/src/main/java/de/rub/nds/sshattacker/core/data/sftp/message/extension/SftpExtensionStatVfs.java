/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionStatVfsHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionStatVfs extends SftpExtensionWithVersion<SftpExtensionStatVfs> {

    public SftpExtensionStatVfs() {
        super();
    }

    public SftpExtensionStatVfs(SftpExtensionStatVfs other) {
        super(other);
    }

    @Override
    public SftpExtensionStatVfs createCopy() {
        return new SftpExtensionStatVfs(this);
    }

    public static final SftpExtensionStatVfsHandler HANDLER = new SftpExtensionStatVfsHandler();

    @Override
    public SftpExtensionStatVfsHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionStatVfsHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionStatVfsHandler.SERIALIZER.serialize(this);
    }
}
