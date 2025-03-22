/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionExpandPath;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionExpandPathHandler
        extends SftpAbstractExtensionHandler<SftpExtensionExpandPath> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionExpandPath object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionExpandPath> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionExpandPath::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionExpandPath> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionExpandPath::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionExpandPath> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.EXPAND_PATH_OPENSSH_COM);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionExpandPath> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
