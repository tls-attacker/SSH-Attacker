/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestMakeTempFolderMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestMakeTempFolderMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestMakeTempFolderMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestMakeTempFolderMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestMakeTempFolderMessageHandler
        extends SftpRequestMessageHandler<SftpRequestMakeTempFolderMessage> {

    @Override
    public SftpRequestMakeTempFolderMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestMakeTempFolderMessageParser(array);
    }

    @Override
    public SftpRequestMakeTempFolderMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestMakeTempFolderMessageParser(array, startPosition);
    }

    public static final SftpRequestMakeTempFolderMessagePreparator PREPARATOR =
            new SftpRequestMakeTempFolderMessagePreparator();

    public static final SftpRequestMakeTempFolderMessageSerializer SERIALIZER =
            new SftpRequestMakeTempFolderMessageSerializer();
}
