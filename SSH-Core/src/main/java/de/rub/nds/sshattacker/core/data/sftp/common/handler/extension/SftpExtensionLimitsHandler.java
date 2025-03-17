/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionLimits;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionLimitsHandler extends SftpAbstractExtensionHandler<SftpExtensionLimits> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionLimits object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionLimits> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionLimits::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionLimits> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionLimits::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionLimits> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.LIMITS_OPENSSH_COM);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionLimits> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
