/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestUsersGroupsByIdMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestUsersGroupsByIdMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestUsersGroupsByIdMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestUsersGroupsByIdMessageHandler
        extends SftpMessageHandler<SftpRequestUsersGroupsByIdMessage> {

    public SftpRequestUsersGroupsByIdMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestUsersGroupsByIdMessageHandler(
            SshContext context, SftpRequestUsersGroupsByIdMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestUsersGroupsByIdMessage
    }

    @Override
    public SftpRequestUsersGroupsByIdMessageParser getParser(byte[] array) {
        return new SftpRequestUsersGroupsByIdMessageParser(array);
    }

    @Override
    public SftpRequestUsersGroupsByIdMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestUsersGroupsByIdMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestUsersGroupsByIdMessagePreparator getPreparator() {
        return new SftpRequestUsersGroupsByIdMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestUsersGroupsByIdMessageSerializer getSerializer() {
        return new SftpRequestUsersGroupsByIdMessageSerializer(message);
    }
}
