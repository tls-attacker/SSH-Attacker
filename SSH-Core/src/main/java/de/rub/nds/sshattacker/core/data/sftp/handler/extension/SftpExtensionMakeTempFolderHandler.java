/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionMakeTempFolder;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionMakeTempFolderHandler
        extends SftpAbstractExtensionHandler<SftpExtensionMakeTempFolder> {

    public SftpExtensionMakeTempFolderHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionMakeTempFolderHandler(
            SshContext context, SftpExtensionMakeTempFolder extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionMakeTempFolder> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionMakeTempFolder::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionMakeTempFolder> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionMakeTempFolder::new, array, startPosition);
    }

    @Override
    public SftpExtensionWithVersionPreparator<SftpExtensionMakeTempFolder> getPreparator() {
        return new SftpExtensionWithVersionPreparator<>(
                context.getChooser(), extension, SftpExtension.MAKE_TEMP_FOLDER);
    }

    @Override
    public SftpExtensionWithVersionSerializer<SftpExtensionMakeTempFolder> getSerializer() {
        return new SftpExtensionWithVersionSerializer<>(extension);
    }
}
