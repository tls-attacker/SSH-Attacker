/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionGetTempFolder;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionGetTempFolderHandler
        extends SftpAbstractExtensionHandler<SftpExtensionGetTempFolder> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionGetTempFolder object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionGetTempFolder> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionGetTempFolder::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionGetTempFolder> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionGetTempFolder::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionGetTempFolder> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.GET_TEMP_FOLDER);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionGetTempFolder> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
