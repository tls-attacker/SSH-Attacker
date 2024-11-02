/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestSpaceAvailableMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestSpaceAvailableMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestSpaceAvailableMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestSpaceAvailableMessageHandler
        extends SftpMessageHandler<SftpRequestSpaceAvailableMessage> {

    public SftpRequestSpaceAvailableMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestSpaceAvailableMessageHandler(
            SshContext context, SftpRequestSpaceAvailableMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestSpaceAvailableMessage
    }

    @Override
    public SftpRequestSpaceAvailableMessageParser getParser(byte[] array) {
        return new SftpRequestSpaceAvailableMessageParser(array);
    }

    @Override
    public SftpRequestSpaceAvailableMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestSpaceAvailableMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestSpaceAvailableMessagePreparator getPreparator() {
        return new SftpRequestSpaceAvailableMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestSpaceAvailableMessageSerializer getSerializer() {
        return new SftpRequestSpaceAvailableMessageSerializer(message);
    }
}
