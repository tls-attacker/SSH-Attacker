/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestFileStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.request.SftpV4RequestFileStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preparator.request.SftpV4RequestFileStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request.SftpV4RequestFileStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4RequestFileStatMessageHandler
        extends SftpRequestMessageHandler<SftpV4RequestFileStatMessage> {

    @Override
    public SftpV4RequestFileStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpV4RequestFileStatMessageParser(array);
    }

    @Override
    public SftpV4RequestFileStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4RequestFileStatMessageParser(array, startPosition);
    }

    public static final SftpV4RequestFileStatMessagePreparator PREPARATOR =
            new SftpV4RequestFileStatMessagePreparator();

    public static final SftpV4RequestFileStatMessageSerializer SERIALIZER =
            new SftpV4RequestFileStatMessageSerializer();
}
