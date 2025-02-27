/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionVendorId;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionVendorIdParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extension.SftpExtensionVendorIdPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionVendorIdSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionVendorIdHandler
        extends SftpAbstractExtensionHandler<SftpExtensionVendorId> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionVendorId object) {}

    @Override
    public SftpExtensionVendorIdParser getParser(byte[] array, SshContext context) {
        return new SftpExtensionVendorIdParser(array);
    }

    @Override
    public SftpExtensionVendorIdParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionVendorIdParser(array, startPosition);
    }

    public static final SftpExtensionVendorIdPreparator PREPARATOR =
            new SftpExtensionVendorIdPreparator();

    public static final SftpExtensionVendorIdSerializer SERIALIZER =
            new SftpExtensionVendorIdSerializer();
}
