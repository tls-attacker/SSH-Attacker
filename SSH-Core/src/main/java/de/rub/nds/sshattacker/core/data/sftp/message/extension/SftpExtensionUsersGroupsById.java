/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionUsersGroupsByIdHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionUsersGroupsById
        extends SftpExtensionWithVersion<SftpExtensionUsersGroupsById> {

    public SftpExtensionUsersGroupsById() {
        super();
    }

    public SftpExtensionUsersGroupsById(SftpExtensionUsersGroupsById other) {
        super(other);
    }

    @Override
    public SftpExtensionUsersGroupsById createCopy() {
        return new SftpExtensionUsersGroupsById(this);
    }

    public static final SftpExtensionUsersGroupsByIdHandler HANDLER =
            new SftpExtensionUsersGroupsByIdHandler();

    @Override
    public SftpExtensionUsersGroupsByIdHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionUsersGroupsByIdHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionUsersGroupsByIdHandler.SERIALIZER.serialize(this);
    }
}
