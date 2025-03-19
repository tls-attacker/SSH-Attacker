/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestHomeDirectoryMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestHomeDirectoryMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request.SftpRequestHomeDirectoryMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestHomeDirectoryMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestHomeDirectoryMessageHandler
        extends SftpRequestMessageHandler<SftpRequestHomeDirectoryMessage> {

    @Override
    public SftpRequestHomeDirectoryMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestHomeDirectoryMessageParser(array);
    }

    @Override
    public SftpRequestHomeDirectoryMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestHomeDirectoryMessageParser(array, startPosition);
    }

    public static final SftpRequestHomeDirectoryMessagePreparator PREPARATOR =
            new SftpRequestHomeDirectoryMessagePreparator();

    public static final SftpRequestHomeDirectoryMessageSerializer SERIALIZER =
            new SftpRequestHomeDirectoryMessageSerializer();
}
