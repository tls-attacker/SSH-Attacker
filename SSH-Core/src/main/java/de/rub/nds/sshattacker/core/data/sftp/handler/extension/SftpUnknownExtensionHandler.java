/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpUnknownExtension;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpUnknownExtensionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpUnknownExtensionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpUnknownExtensionSerializer;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpUnknownExtensionHandler
        extends SftpAbstractExtensionHandler<SftpUnknownExtension> {

    public SftpUnknownExtensionHandler(SshContext context) {
        super(context);
    }

    public SftpUnknownExtensionHandler(SshContext context, SftpUnknownExtension extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpUnknownExtensionParser getParser(byte[] array) {
        return new SftpUnknownExtensionParser(array);
    }

    @Override
    public SftpUnknownExtensionParser getParser(byte[] array, int startPosition) {
        return new SftpUnknownExtensionParser(array, startPosition);
    }

    @Override
    public Preparator<SftpUnknownExtension> getPreparator() {
        return new SftpUnknownExtensionPreparator(context.getChooser(), extension);
    }

    @Override
    public SftpUnknownExtensionSerializer getSerializer() {
        return new SftpUnknownExtensionSerializer(extension);
    }
}
