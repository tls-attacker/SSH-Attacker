/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestHardlinkMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestHardlinkMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestHardlinkMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestHardlinkMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestHardlinkMessageHandler
        extends SftpMessageHandler<SftpRequestHardlinkMessage> {

    public SftpRequestHardlinkMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestHardlinkMessageHandler(
            SshContext context, SftpRequestHardlinkMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestHardlinkMessage
    }

    @Override
    public SftpRequestHardlinkMessageParser getParser(byte[] array) {
        return new SftpRequestHardlinkMessageParser(array);
    }

    @Override
    public SftpRequestHardlinkMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestHardlinkMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestHardlinkMessagePreparator getPreparator() {
        return new SftpRequestHardlinkMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestHardlinkMessageSerializer getSerializer() {
        return new SftpRequestHardlinkMessageSerializer(message);
    }
}
