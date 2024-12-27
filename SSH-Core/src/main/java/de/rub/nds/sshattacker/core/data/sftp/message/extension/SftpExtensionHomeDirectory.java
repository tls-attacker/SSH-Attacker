/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionHomeDirectoryHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionHomeDirectory
        extends SftpExtensionWithVersion<SftpExtensionHomeDirectory> {

    public SftpExtensionHomeDirectory() {
        super();
    }

    public SftpExtensionHomeDirectory(SftpExtensionHomeDirectory other) {
        super(other);
    }

    @Override
    public SftpExtensionHomeDirectory createCopy() {
        return new SftpExtensionHomeDirectory(this);
    }

    @Override
    public SftpExtensionHomeDirectoryHandler getHandler(SshContext context) {
        return new SftpExtensionHomeDirectoryHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionHomeDirectoryHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionHomeDirectoryHandler.SERIALIZER.serialize(this);
    }
}
