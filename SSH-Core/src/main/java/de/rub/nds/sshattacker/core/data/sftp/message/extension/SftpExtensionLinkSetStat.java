/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionLinkSetStatHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionLinkSetStat extends SftpExtensionWithVersion<SftpExtensionLinkSetStat> {

    public SftpExtensionLinkSetStat() {
        super();
    }

    public SftpExtensionLinkSetStat(SftpExtensionLinkSetStat other) {
        super(other);
    }

    @Override
    public SftpExtensionLinkSetStat createCopy() {
        return new SftpExtensionLinkSetStat(this);
    }

    public static final SftpExtensionLinkSetStatHandler HANDLER =
            new SftpExtensionLinkSetStatHandler();

    @Override
    public SftpExtensionLinkSetStatHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionLinkSetStatHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionLinkSetStatHandler.SERIALIZER.serialize(this);
    }
}
