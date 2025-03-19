/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_response.SftpResponseSpaceAvailableMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_response.SftpResponseSpaceAvailableMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_response.SftpResponseSpaceAvailableMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseSpaceAvailableMessageHandler
        extends SftpResponseMessageHandler<SftpResponseSpaceAvailableMessage> {

    @Override
    public SftpResponseSpaceAvailableMessageParser getParser(byte[] array, SshContext context) {
        return new SftpResponseSpaceAvailableMessageParser(array);
    }

    @Override
    public SftpResponseSpaceAvailableMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpResponseSpaceAvailableMessageParser(array, startPosition);
    }

    public static final SftpResponseSpaceAvailableMessagePreparator PREPARATOR =
            new SftpResponseSpaceAvailableMessagePreparator();

    public static final SftpResponseSpaceAvailableMessageSerializer SERIALIZER =
            new SftpResponseSpaceAvailableMessageSerializer();
}
