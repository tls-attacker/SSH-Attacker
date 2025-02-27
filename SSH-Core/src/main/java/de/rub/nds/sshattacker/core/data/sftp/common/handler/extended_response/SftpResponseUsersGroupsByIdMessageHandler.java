/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_response.SftpResponseUsersGroupsByIdMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_response.SftpResponseUsersGroupsByIdMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_response.SftpResponseUsersGroupsByIdMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseUsersGroupsByIdMessageHandler
        extends SftpResponseMessageHandler<SftpResponseUsersGroupsByIdMessage> {

    @Override
    public SftpResponseUsersGroupsByIdMessageParser getParser(byte[] array, SshContext context) {
        return new SftpResponseUsersGroupsByIdMessageParser(array);
    }

    @Override
    public SftpResponseUsersGroupsByIdMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpResponseUsersGroupsByIdMessageParser(array, startPosition);
    }

    public static final SftpResponseUsersGroupsByIdMessagePreparator PREPARATOR =
            new SftpResponseUsersGroupsByIdMessagePreparator();

    public static final SftpResponseUsersGroupsByIdMessageSerializer SERIALIZER =
            new SftpResponseUsersGroupsByIdMessageSerializer();
}
