/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionNewline;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionNewlineParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionNewlinePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionNewlineSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionNewlineHandler
        extends SftpAbstractExtensionHandler<SftpExtensionNewline> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionNewline object) {}

    @Override
    public SftpExtensionNewlineParser getParser(byte[] array, SshContext context) {
        return new SftpExtensionNewlineParser(array);
    }

    @Override
    public SftpExtensionNewlineParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionNewlineParser(array, startPosition);
    }

    public static final SftpExtensionNewlinePreparator PREPARATOR =
            new SftpExtensionNewlinePreparator();

    public static final SftpExtensionNewlineSerializer SERIALIZER =
            new SftpExtensionNewlineSerializer();
}
