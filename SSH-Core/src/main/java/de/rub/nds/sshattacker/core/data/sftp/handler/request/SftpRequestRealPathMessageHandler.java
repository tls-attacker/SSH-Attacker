/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRealPathMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestRealPathMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestRealPathMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestRealPathMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRealPathMessageHandler
        extends SftpRequestMessageHandler<SftpRequestRealPathMessage> {

    @Override
    public SftpRequestRealPathMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestRealPathMessageParser(array);
    }

    @Override
    public SftpRequestRealPathMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestRealPathMessageParser(array, startPosition);
    }

    public static final SftpRequestRealPathMessagePreparator PREPARATOR =
            new SftpRequestRealPathMessagePreparator();

    public static final SftpRequestRealPathMessageSerializer SERIALIZER =
            new SftpRequestRealPathMessageSerializer();
}
