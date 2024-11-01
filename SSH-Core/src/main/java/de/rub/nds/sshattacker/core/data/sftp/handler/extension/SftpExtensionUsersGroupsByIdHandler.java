/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionUsersGroupsById;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionUsersGroupsByIdHandler
        extends SftpAbstractExtensionHandler<SftpExtensionUsersGroupsById> {

    public SftpExtensionUsersGroupsByIdHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionUsersGroupsByIdHandler(
            SshContext context, SftpExtensionUsersGroupsById extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionUsersGroupsById> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionUsersGroupsById::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionUsersGroupsById> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionUsersGroupsById::new, array, startPosition);
    }

    @Override
    public SftpExtensionWithVersionPreparator<SftpExtensionUsersGroupsById> getPreparator() {
        return new SftpExtensionWithVersionPreparator<>(
                context.getChooser(), extension, SftpExtension.USERS_GROUPS_BY_ID);
    }

    @Override
    public SftpExtensionWithVersionSerializer<SftpExtensionUsersGroupsById> getSerializer() {
        return new SftpExtensionWithVersionSerializer<>(extension);
    }
}
