/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseCheckFileMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_response.SftpResponseCheckFileMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_response.SftpResponseCheckFileMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_response.SftpResponseCheckFileMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseCheckFileMessageHandler
        extends SftpResponseMessageHandler<SftpResponseCheckFileMessage> {

    @Override
    public SftpResponseCheckFileMessageParser getParser(byte[] array, SshContext context) {
        return new SftpResponseCheckFileMessageParser(array);
    }

    @Override
    public SftpResponseCheckFileMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpResponseCheckFileMessageParser(array, startPosition);
    }

    public static final SftpResponseCheckFileMessagePreparator PREPARATOR =
            new SftpResponseCheckFileMessagePreparator();

    public static final SftpResponseCheckFileMessageSerializer SERIALIZER =
            new SftpResponseCheckFileMessageSerializer();
}
