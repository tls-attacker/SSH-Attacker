/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestCopyDataMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestCopyDataMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request.SftpRequestCopyDataMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestCopyDataMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCopyDataMessageHandler
        extends SftpRequestMessageHandler<SftpRequestCopyDataMessage> {

    @Override
    public SftpRequestCopyDataMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestCopyDataMessageParser(array);
    }

    @Override
    public SftpRequestCopyDataMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestCopyDataMessageParser(array, startPosition);
    }

    public static final SftpRequestCopyDataMessagePreparator PREPARATOR =
            new SftpRequestCopyDataMessagePreparator();

    public static final SftpRequestCopyDataMessageSerializer SERIALIZER =
            new SftpRequestCopyDataMessageSerializer();
}
