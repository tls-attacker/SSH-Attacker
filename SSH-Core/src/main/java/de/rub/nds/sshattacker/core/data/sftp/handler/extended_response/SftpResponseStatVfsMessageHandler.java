/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseStatVfsMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_response.SftpResponseStatVfsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response.SftpResponseStatVfsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response.SftpResponseStatVfsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseStatVfsMessageHandler
        extends SftpResponseMessageHandler<SftpResponseStatVfsMessage> {

    public SftpResponseStatVfsMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseStatVfsMessageHandler(
            SshContext context, SftpResponseStatVfsMessage message) {
        super(context, message);
    }

    @Override
    public SftpResponseStatVfsMessageParser getParser(byte[] array) {
        return new SftpResponseStatVfsMessageParser(array);
    }

    @Override
    public SftpResponseStatVfsMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseStatVfsMessageParser(array, startPosition);
    }

    @Override
    public SftpResponseStatVfsMessagePreparator getPreparator() {
        return new SftpResponseStatVfsMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpResponseStatVfsMessageSerializer getSerializer() {
        return new SftpResponseStatVfsMessageSerializer(message);
    }
}
