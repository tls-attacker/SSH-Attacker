/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionCopyDataHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionCopyData extends SftpExtensionWithVersion<SftpExtensionCopyData> {

    public SftpExtensionCopyData() {
        super();
    }

    public SftpExtensionCopyData(SftpExtensionCopyData other) {
        super(other);
    }

    @Override
    public SftpExtensionCopyData createCopy() {
        return new SftpExtensionCopyData(this);
    }

    public static final SftpExtensionCopyDataHandler HANDLER = new SftpExtensionCopyDataHandler();

    @Override
    public SftpExtensionCopyDataHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionCopyDataHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionCopyDataHandler.SERIALIZER.serialize(this);
    }
}
