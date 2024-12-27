/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionTextSeek;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionTextSeekHandler
        extends SftpAbstractExtensionHandler<SftpExtensionTextSeek> {

    public SftpExtensionTextSeekHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionTextSeekHandler(SshContext context, SftpExtensionTextSeek extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionTextSeek> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionTextSeek::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionTextSeek> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionTextSeek::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionTextSeek> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.TEXT_SEEK);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionTextSeek> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
