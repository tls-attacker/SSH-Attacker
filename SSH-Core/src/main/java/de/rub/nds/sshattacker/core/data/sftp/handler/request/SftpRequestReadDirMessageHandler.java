/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestReadDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestReadDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestReadDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestReadDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestReadDirMessageHandler
        extends SftpRequestMessageHandler<SftpRequestReadDirMessage> {

    @Override
    public SftpRequestReadDirMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestReadDirMessageParser(array);
    }

    @Override
    public SftpRequestReadDirMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestReadDirMessageParser(array, startPosition);
    }

    public static final SftpRequestReadDirMessagePreparator PREPARATOR =
            new SftpRequestReadDirMessagePreparator();

    public static final SftpRequestReadDirMessageSerializer SERIALIZER =
            new SftpRequestReadDirMessageSerializer();
}
