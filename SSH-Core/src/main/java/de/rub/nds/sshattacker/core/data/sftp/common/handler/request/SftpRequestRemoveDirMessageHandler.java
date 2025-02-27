/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestRemoveDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestRemoveDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.request.SftpRequestRemoveDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestRemoveDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRemoveDirMessageHandler
        extends SftpRequestMessageHandler<SftpRequestRemoveDirMessage> {

    @Override
    public SftpRequestRemoveDirMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestRemoveDirMessageParser(array);
    }

    @Override
    public SftpRequestRemoveDirMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestRemoveDirMessageParser(array, startPosition);
    }

    public static final SftpRequestRemoveDirMessagePreparator PREPARATOR =
            new SftpRequestRemoveDirMessagePreparator();

    public static final SftpRequestRemoveDirMessageSerializer SERIALIZER =
            new SftpRequestRemoveDirMessageSerializer();
}
