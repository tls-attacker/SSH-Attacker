/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.request.SftpRequestStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestStatMessage> {

    @Override
    public SftpRequestStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestStatMessageParser(array);
    }

    @Override
    public SftpRequestStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestStatMessageParser(array, startPosition);
    }

    public static final SftpRequestStatMessagePreparator PREPARATOR =
            new SftpRequestStatMessagePreparator();

    public static final SftpRequestStatMessageSerializer SERIALIZER =
            new SftpRequestStatMessageSerializer();
}
