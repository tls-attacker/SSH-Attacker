/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionUsersGroupsById;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionUsersGroupsByIdHandler
        extends SftpAbstractExtensionHandler<SftpExtensionUsersGroupsById> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionUsersGroupsById object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionUsersGroupsById> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionUsersGroupsById::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionUsersGroupsById> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionUsersGroupsById::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionUsersGroupsById>
            PREPARATOR =
                    new SftpExtensionWithVersionPreparator<>(
                            SftpExtension.USERS_GROUPS_BY_ID_OPENSSH_COM);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionUsersGroupsById>
            SERIALIZER = new SftpExtensionWithVersionSerializer<>();
}
