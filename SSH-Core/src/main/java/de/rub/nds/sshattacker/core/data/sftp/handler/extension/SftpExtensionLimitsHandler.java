/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionLimits;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionLimitsHandler extends SftpAbstractExtensionHandler<SftpExtensionLimits> {

    public SftpExtensionLimitsHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionLimitsHandler(SshContext context, SftpExtensionLimits extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionLimits> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionLimits::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionLimits> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionLimits::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionLimits> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.LIMITS);

    @Override
    public SftpExtensionWithVersionSerializer<SftpExtensionLimits> getSerializer() {
        return new SftpExtensionWithVersionSerializer<>(extension);
    }
}
