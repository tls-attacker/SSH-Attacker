/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCheckFileHandleMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestCheckFileHandleMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestCheckFileHandleMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestCheckFileHandleMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCheckFileHandleMessageHandler
        extends SftpRequestMessageHandler<SftpRequestCheckFileHandleMessage> {

    @Override
    public SftpRequestCheckFileHandleMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestCheckFileHandleMessageParser(array);
    }

    @Override
    public SftpRequestCheckFileHandleMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestCheckFileHandleMessageParser(array, startPosition);
    }

    public static final SftpRequestCheckFileHandleMessagePreparator PREPARATOR =
            new SftpRequestCheckFileHandleMessagePreparator();

    public static final SftpRequestCheckFileHandleMessageSerializer SERIALIZER =
            new SftpRequestCheckFileHandleMessageSerializer();
}
