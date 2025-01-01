/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionExpandPathHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionExpandPath extends SftpExtensionWithVersion<SftpExtensionExpandPath> {

    public SftpExtensionExpandPath() {
        super();
    }

    public SftpExtensionExpandPath(SftpExtensionExpandPath other) {
        super(other);
    }

    @Override
    public SftpExtensionExpandPath createCopy() {
        return new SftpExtensionExpandPath(this);
    }

    public static final SftpExtensionExpandPathHandler HANDLER =
            new SftpExtensionExpandPathHandler();

    @Override
    public SftpExtensionExpandPathHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionExpandPathHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionExpandPathHandler.SERIALIZER.serialize(this);
    }
}
