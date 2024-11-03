/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestHomeDirectoryMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestHomeDirectoryMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestHomeDirectoryMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestHomeDirectoryMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestHomeDirectoryMessageHandler
        extends SftpRequestMessageHandler<SftpRequestHomeDirectoryMessage> {

    public SftpRequestHomeDirectoryMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestHomeDirectoryMessageHandler(
            SshContext context, SftpRequestHomeDirectoryMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestHomeDirectoryMessageParser getParser(byte[] array) {
        return new SftpRequestHomeDirectoryMessageParser(array);
    }

    @Override
    public SftpRequestHomeDirectoryMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestHomeDirectoryMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestHomeDirectoryMessagePreparator getPreparator() {
        return new SftpRequestHomeDirectoryMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestHomeDirectoryMessageSerializer getSerializer() {
        return new SftpRequestHomeDirectoryMessageSerializer(message);
    }
}
