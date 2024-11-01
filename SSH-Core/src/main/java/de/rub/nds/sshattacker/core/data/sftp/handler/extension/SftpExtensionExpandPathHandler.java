/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionExpandPath;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionExpandPathHandler
        extends SftpAbstractExtensionHandler<SftpExtensionExpandPath> {

    public SftpExtensionExpandPathHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionExpandPathHandler(SshContext context, SftpExtensionExpandPath extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionExpandPath> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionExpandPath::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionExpandPath> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionExpandPath::new, array, startPosition);
    }

    @Override
    public SftpExtensionWithVersionPreparator<SftpExtensionExpandPath> getPreparator() {
        return new SftpExtensionWithVersionPreparator<>(
                context.getChooser(), extension, SftpExtension.EXPAND_PATH);
    }

    @Override
    public SftpExtensionWithVersionSerializer<SftpExtensionExpandPath> getSerializer() {
        return new SftpExtensionWithVersionSerializer<>(extension);
    }
}
