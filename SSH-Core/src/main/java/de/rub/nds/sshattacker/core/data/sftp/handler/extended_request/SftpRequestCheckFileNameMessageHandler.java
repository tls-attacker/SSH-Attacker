/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCheckFileNameMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestCheckFileNameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestCheckFileNameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestCheckFileNameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCheckFileNameMessageHandler
        extends SftpMessageHandler<SftpRequestCheckFileNameMessage> {

    public SftpRequestCheckFileNameMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestCheckFileNameMessageHandler(
            SshContext context, SftpRequestCheckFileNameMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestCheckFileNameMessage
    }

    @Override
    public SftpRequestCheckFileNameMessageParser getParser(byte[] array) {
        return new SftpRequestCheckFileNameMessageParser(array);
    }

    @Override
    public SftpRequestCheckFileNameMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestCheckFileNameMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestCheckFileNameMessagePreparator getPreparator() {
        return new SftpRequestCheckFileNameMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestCheckFileNameMessageSerializer getSerializer() {
        return new SftpRequestCheckFileNameMessageSerializer(message);
    }
}
