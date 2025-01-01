/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestUsersGroupsByIdMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestUsersGroupsByIdMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestUsersGroupsByIdMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestUsersGroupsByIdMessageHandler
        extends SftpRequestMessageHandler<SftpRequestUsersGroupsByIdMessage> {

    @Override
    public SftpRequestUsersGroupsByIdMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestUsersGroupsByIdMessageParser(array);
    }

    @Override
    public SftpRequestUsersGroupsByIdMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestUsersGroupsByIdMessageParser(array, startPosition);
    }

    public static final SftpRequestUsersGroupsByIdMessagePreparator PREPARATOR =
            new SftpRequestUsersGroupsByIdMessagePreparator();

    public static final SftpRequestUsersGroupsByIdMessageSerializer SERIALIZER =
            new SftpRequestUsersGroupsByIdMessageSerializer();
}
