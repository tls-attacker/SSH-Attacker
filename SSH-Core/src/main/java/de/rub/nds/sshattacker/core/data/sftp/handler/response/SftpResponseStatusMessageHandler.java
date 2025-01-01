/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseStatusMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseStatusMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.response.SftpResponseStatusMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseStatusMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseStatusMessageHandler
        extends SftpResponseMessageHandler<SftpResponseStatusMessage> {

    @Override
    public SftpResponseStatusMessageParser getParser(byte[] array, SshContext context) {
        return new SftpResponseStatusMessageParser(array);
    }

    @Override
    public SftpResponseStatusMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpResponseStatusMessageParser(array, startPosition);
    }

    public static final SftpResponseStatusMessagePreparator PREPARATOR =
            new SftpResponseStatusMessagePreparator();

    public static final SftpResponseStatusMessageSerializer SERIALIZER =
            new SftpResponseStatusMessageSerializer();
}
