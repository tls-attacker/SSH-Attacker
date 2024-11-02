/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_response.SftpResponseUnknownMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response.SftpResponseUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response.SftpResponseUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseUnknownMessageHandler
        extends SftpMessageHandler<SftpResponseUnknownMessage> {

    public SftpResponseUnknownMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseUnknownMessageHandler(
            SshContext context, SftpResponseUnknownMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpResponseUnknownMessage
    }

    @Override
    public SftpResponseUnknownMessageParser getParser(byte[] array) {
        return new SftpResponseUnknownMessageParser(array);
    }

    @Override
    public SftpResponseUnknownMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseUnknownMessageParser(array, startPosition);
    }

    @Override
    public SftpResponseUnknownMessagePreparator getPreparator() {
        return new SftpResponseUnknownMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpResponseUnknownMessageSerializer getSerializer() {
        return new SftpResponseUnknownMessageSerializer(message);
    }
}
