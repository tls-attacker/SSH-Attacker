/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestMakeDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestMakeDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.request.SftpRequestMakeDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestMakeDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestMakeDirMessageHandler
        extends SftpRequestMessageHandler<SftpRequestMakeDirMessage> {

    @Override
    public SftpRequestMakeDirMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestMakeDirMessageParser(array);
    }

    @Override
    public SftpRequestMakeDirMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestMakeDirMessageParser(array, startPosition);
    }

    public static final SftpRequestMakeDirMessagePreparator PREPARATOR =
            new SftpRequestMakeDirMessagePreparator();

    public static final SftpRequestMakeDirMessageSerializer SERIALIZER =
            new SftpRequestMakeDirMessageSerializer();
}
