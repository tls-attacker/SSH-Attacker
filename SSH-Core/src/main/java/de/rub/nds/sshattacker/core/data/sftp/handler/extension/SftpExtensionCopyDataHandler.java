/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionCopyData;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionCopyDataHandler
        extends SftpAbstractExtensionHandler<SftpExtensionCopyData> {

    public SftpExtensionCopyDataHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionCopyDataHandler(SshContext context, SftpExtensionCopyData extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionCopyData> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionCopyData::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionCopyData> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionCopyData::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionCopyData> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.COPY_DATA);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionCopyData> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
