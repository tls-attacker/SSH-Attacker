/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.extension.SftpExtensionHardlinkHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionHardlink extends SftpExtensionWithVersion<SftpExtensionHardlink> {

    public SftpExtensionHardlink() {
        super();
    }

    public SftpExtensionHardlink(SftpExtensionHardlink other) {
        super(other);
    }

    @Override
    public SftpExtensionHardlink createCopy() {
        return new SftpExtensionHardlink(this);
    }

    public static final SftpExtensionHardlinkHandler HANDLER = new SftpExtensionHardlinkHandler();

    @Override
    public SftpExtensionHardlinkHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionHardlinkHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionHardlinkHandler.SERIALIZER.serialize(this);
    }
}
