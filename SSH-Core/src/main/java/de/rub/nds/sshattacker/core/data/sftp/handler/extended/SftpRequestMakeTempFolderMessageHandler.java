/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestMakeTempFolderMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestMakeTempFolderMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestMakeTempFolderMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestMakeTempFolderMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestMakeTempFolderMessageHandler
        extends SftpMessageHandler<SftpRequestMakeTempFolderMessage> {

    public SftpRequestMakeTempFolderMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestMakeTempFolderMessageHandler(
            SshContext context, SftpRequestMakeTempFolderMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestMakeTempFolderMessage
    }

    @Override
    public SftpRequestMakeTempFolderMessageParser getParser(byte[] array) {
        return new SftpRequestMakeTempFolderMessageParser(array);
    }

    @Override
    public SftpRequestMakeTempFolderMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestMakeTempFolderMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestMakeTempFolderMessagePreparator getPreparator() {
        return new SftpRequestMakeTempFolderMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestMakeTempFolderMessageSerializer getSerializer() {
        return new SftpRequestMakeTempFolderMessageSerializer(message);
    }
}
