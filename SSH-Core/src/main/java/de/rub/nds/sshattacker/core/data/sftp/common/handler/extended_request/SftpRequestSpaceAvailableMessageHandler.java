/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestSpaceAvailableMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request.SftpRequestSpaceAvailableMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestSpaceAvailableMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestSpaceAvailableMessageHandler
        extends SftpRequestMessageHandler<SftpRequestSpaceAvailableMessage> {

    @Override
    public SftpRequestSpaceAvailableMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestSpaceAvailableMessageParser(array);
    }

    @Override
    public SftpRequestSpaceAvailableMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestSpaceAvailableMessageParser(array, startPosition);
    }

    public static final SftpRequestSpaceAvailableMessagePreparator PREPARATOR =
            new SftpRequestSpaceAvailableMessagePreparator();

    public static final SftpRequestSpaceAvailableMessageSerializer SERIALIZER =
            new SftpRequestSpaceAvailableMessageSerializer();
}
