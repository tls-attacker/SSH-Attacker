/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_response.SftpResponseUsersGroupsByIdMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response.SftpResponseUsersGroupsByIdMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response.SftpResponseUsersGroupsByIdMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseUsersGroupsByIdMessageHandler
        extends SftpResponseMessageHandler<SftpResponseUsersGroupsByIdMessage> {

    public SftpResponseUsersGroupsByIdMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseUsersGroupsByIdMessageHandler(
            SshContext context, SftpResponseUsersGroupsByIdMessage message) {
        super(context, message);
    }

    @Override
    public SftpResponseUsersGroupsByIdMessageParser getParser(byte[] array) {
        return new SftpResponseUsersGroupsByIdMessageParser(array);
    }

    @Override
    public SftpResponseUsersGroupsByIdMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseUsersGroupsByIdMessageParser(array, startPosition);
    }

    public static final SftpResponseUsersGroupsByIdMessagePreparator PREPARATOR =
            new SftpResponseUsersGroupsByIdMessagePreparator();

    @Override
    public SftpResponseUsersGroupsByIdMessageSerializer getSerializer() {
        return new SftpResponseUsersGroupsByIdMessageSerializer(message);
    }
}
