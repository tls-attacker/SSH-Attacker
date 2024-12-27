/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseCheckFileMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_response.SftpResponseCheckFileMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response.SftpResponseCheckFileMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response.SftpResponseCheckFileMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseCheckFileMessageHandler
        extends SftpResponseMessageHandler<SftpResponseCheckFileMessage> {

    public SftpResponseCheckFileMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseCheckFileMessageHandler(
            SshContext context, SftpResponseCheckFileMessage message) {
        super(context, message);
    }

    @Override
    public SftpResponseCheckFileMessageParser getParser(byte[] array) {
        return new SftpResponseCheckFileMessageParser(array);
    }

    @Override
    public SftpResponseCheckFileMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseCheckFileMessageParser(array, startPosition);
    }

    public static final SftpResponseCheckFileMessagePreparator PREPARATOR =
            new SftpResponseCheckFileMessagePreparator();

    @Override
    public SftpResponseCheckFileMessageSerializer getSerializer() {
        return new SftpResponseCheckFileMessageSerializer(message);
    }
}
