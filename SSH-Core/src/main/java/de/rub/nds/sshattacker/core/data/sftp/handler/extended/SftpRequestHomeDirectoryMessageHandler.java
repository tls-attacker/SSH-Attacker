/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestHomeDirectoryMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestHomeDirectoryMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestHomeDirectoryMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestHomeDirectoryMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestHomeDirectoryMessageHandler
        extends SftpMessageHandler<SftpRequestHomeDirectoryMessage> {

    public SftpRequestHomeDirectoryMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestHomeDirectoryMessageHandler(
            SshContext context, SftpRequestHomeDirectoryMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestHomeDirectoryMessage
    }

    @Override
    public SftpRequestHomeDirectoryMessageParser getParser(byte[] array) {
        return new SftpRequestHomeDirectoryMessageParser(array);
    }

    @Override
    public SftpRequestHomeDirectoryMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestHomeDirectoryMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestHomeDirectoryMessagePreparator getPreparator() {
        return new SftpRequestHomeDirectoryMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestHomeDirectoryMessageSerializer getSerializer() {
        return new SftpRequestHomeDirectoryMessageSerializer(message);
    }
}
