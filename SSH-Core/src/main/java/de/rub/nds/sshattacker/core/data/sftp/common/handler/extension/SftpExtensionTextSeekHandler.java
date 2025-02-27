/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionTextSeek;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionTextSeekHandler
        extends SftpAbstractExtensionHandler<SftpExtensionTextSeek> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionTextSeek object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionTextSeek> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionTextSeek::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionTextSeek> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionTextSeek::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionTextSeek> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.TEXT_SEEK);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionTextSeek> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
