/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.extension.SftpExtensionLimitsHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionLimits extends SftpExtensionWithVersion<SftpExtensionLimits> {

    public SftpExtensionLimits() {
        super();
    }

    public SftpExtensionLimits(SftpExtensionLimits other) {
        super(other);
    }

    @Override
    public SftpExtensionLimits createCopy() {
        return new SftpExtensionLimits(this);
    }

    public static final SftpExtensionLimitsHandler HANDLER = new SftpExtensionLimitsHandler();

    @Override
    public SftpExtensionLimitsHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionLimitsHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionLimitsHandler.SERIALIZER.serialize(this);
    }
}
