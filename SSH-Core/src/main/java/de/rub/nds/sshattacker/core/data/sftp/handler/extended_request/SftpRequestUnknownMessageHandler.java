/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestUnknownMessageHandler
        extends SftpRequestMessageHandler<SftpRequestUnknownMessage> {

    @Override
    public SftpRequestUnknownMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestUnknownMessageParser(array);
    }

    @Override
    public SftpRequestUnknownMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestUnknownMessageParser(array, startPosition);
    }

    public static final SftpRequestUnknownMessagePreparator PREPARATOR =
            new SftpRequestUnknownMessagePreparator();

    public static final SftpRequestUnknownMessageSerializer SERIALIZER =
            new SftpRequestUnknownMessageSerializer();
}
