/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_response.SftpResponseSpaceAvailableMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response.SftpResponseSpaceAvailableMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response.SftpResponseSpaceAvailableMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseSpaceAvailableMessageHandler
        extends SftpResponseMessageHandler<SftpResponseSpaceAvailableMessage> {

    public SftpResponseSpaceAvailableMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseSpaceAvailableMessageHandler(
            SshContext context, SftpResponseSpaceAvailableMessage message) {
        super(context, message);
    }

    @Override
    public SftpResponseSpaceAvailableMessageParser getParser(byte[] array) {
        return new SftpResponseSpaceAvailableMessageParser(array);
    }

    @Override
    public SftpResponseSpaceAvailableMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseSpaceAvailableMessageParser(array, startPosition);
    }

    public static final SftpResponseSpaceAvailableMessagePreparator PREPARATOR =
            new SftpResponseSpaceAvailableMessagePreparator();

    @Override
    public SftpResponseSpaceAvailableMessageSerializer getSerializer() {
        return new SftpResponseSpaceAvailableMessageSerializer(message);
    }
}
