/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestFileStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestFileStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.request.SftpRequestFileStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestFileStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestFileStatMessage> {

    @Override
    public SftpRequestFileStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestFileStatMessageParser(array);
    }

    @Override
    public SftpRequestFileStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestFileStatMessageParser(array, startPosition);
    }

    public static final SftpRequestFileStatMessagePreparator PREPARATOR =
            new SftpRequestFileStatMessagePreparator();

    public static final SftpRequestFileStatMessageSerializer SERIALIZER =
            new SftpRequestFileStatMessageSerializer();
}
