/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestWriteMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestWriteMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestWriteMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestWriteMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestWriteMessageHandler
        extends SftpRequestMessageHandler<SftpRequestWriteMessage> {

    @Override
    public SftpRequestWriteMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestWriteMessageParser(array);
    }

    @Override
    public SftpRequestWriteMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestWriteMessageParser(array, startPosition);
    }

    public static final SftpRequestWriteMessagePreparator PREPARATOR =
            new SftpRequestWriteMessagePreparator();

    public static final SftpRequestWriteMessageSerializer SERIALIZER =
            new SftpRequestWriteMessageSerializer();
}
