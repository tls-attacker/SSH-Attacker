/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestGetTempFolderMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestGetTempFolderMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestGetTempFolderMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestGetTempFolderMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestGetTempFolderMessageHandler
        extends SftpRequestMessageHandler<SftpRequestGetTempFolderMessage> {

    @Override
    public SftpRequestGetTempFolderMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestGetTempFolderMessageParser(array);
    }

    @Override
    public SftpRequestGetTempFolderMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestGetTempFolderMessageParser(array, startPosition);
    }

    public static final SftpRequestGetTempFolderMessagePreparator PREPARATOR =
            new SftpRequestGetTempFolderMessagePreparator();

    public static final SftpRequestGetTempFolderMessageSerializer SERIALIZER =
            new SftpRequestGetTempFolderMessageSerializer();
}
