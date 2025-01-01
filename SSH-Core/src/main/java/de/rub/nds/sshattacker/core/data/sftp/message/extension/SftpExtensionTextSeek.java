/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionTextSeekHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionTextSeek extends SftpExtensionWithVersion<SftpExtensionTextSeek> {

    public SftpExtensionTextSeek() {
        super();
    }

    public SftpExtensionTextSeek(SftpExtensionTextSeek other) {
        super(other);
    }

    @Override
    public SftpExtensionTextSeek createCopy() {
        return new SftpExtensionTextSeek(this);
    }

    public static final SftpExtensionTextSeekHandler HANDLER = new SftpExtensionTextSeekHandler();

    @Override
    public SftpExtensionTextSeekHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionTextSeekHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionTextSeekHandler.SERIALIZER.serialize(this);
    }
}
