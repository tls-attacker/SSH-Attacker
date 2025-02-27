/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestCheckFileNameMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestCheckFileNameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request.SftpRequestCheckFileNameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestCheckFileNameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCheckFileNameMessageHandler
        extends SftpRequestMessageHandler<SftpRequestCheckFileNameMessage> {

    @Override
    public SftpRequestCheckFileNameMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestCheckFileNameMessageParser(array);
    }

    @Override
    public SftpRequestCheckFileNameMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestCheckFileNameMessageParser(array, startPosition);
    }

    public static final SftpRequestCheckFileNameMessagePreparator PREPARATOR =
            new SftpRequestCheckFileNameMessagePreparator();

    public static final SftpRequestCheckFileNameMessageSerializer SERIALIZER =
            new SftpRequestCheckFileNameMessageSerializer();
}
