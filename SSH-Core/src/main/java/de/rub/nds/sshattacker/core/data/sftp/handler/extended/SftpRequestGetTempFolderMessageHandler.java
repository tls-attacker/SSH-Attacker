/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestGetTempFolderMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestGetTempFolderMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestGetTempFolderMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestGetTempFolderMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestGetTempFolderMessageHandler
        extends SftpMessageHandler<SftpRequestGetTempFolderMessage> {

    public SftpRequestGetTempFolderMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestGetTempFolderMessageHandler(
            SshContext context, SftpRequestGetTempFolderMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestGetTempFolderMessage
    }

    @Override
    public SftpRequestGetTempFolderMessageParser getParser(byte[] array) {
        return new SftpRequestGetTempFolderMessageParser(array);
    }

    @Override
    public SftpRequestGetTempFolderMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestGetTempFolderMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestGetTempFolderMessagePreparator getPreparator() {
        return new SftpRequestGetTempFolderMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestGetTempFolderMessageSerializer getSerializer() {
        return new SftpRequestGetTempFolderMessageSerializer(message);
    }
}
