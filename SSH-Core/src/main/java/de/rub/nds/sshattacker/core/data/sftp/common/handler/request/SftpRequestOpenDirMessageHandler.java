/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestOpenDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestOpenDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.request.SftpRequestOpenDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestOpenDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestOpenDirMessageHandler
        extends SftpRequestMessageHandler<SftpRequestOpenDirMessage> {

    @Override
    public SftpRequestOpenDirMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestOpenDirMessageParser(array);
    }

    @Override
    public SftpRequestOpenDirMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestOpenDirMessageParser(array, startPosition);
    }

    public static final SftpRequestOpenDirMessagePreparator PREPARATOR =
            new SftpRequestOpenDirMessagePreparator();

    public static final SftpRequestOpenDirMessageSerializer SERIALIZER =
            new SftpRequestOpenDirMessageSerializer();
}
