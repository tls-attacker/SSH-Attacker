/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestFileSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestFileSetStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.request.SftpRequestFileSetStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestFileSetStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileSetStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestFileSetStatMessage> {

    @Override
    public SftpRequestFileSetStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestFileSetStatMessageParser(array);
    }

    @Override
    public SftpRequestFileSetStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestFileSetStatMessageParser(array, startPosition);
    }

    public static final SftpRequestFileSetStatMessagePreparator PREPARATOR =
            new SftpRequestFileSetStatMessagePreparator();

    public static final SftpRequestFileSetStatMessageSerializer SERIALIZER =
            new SftpRequestFileSetStatMessageSerializer();
}
