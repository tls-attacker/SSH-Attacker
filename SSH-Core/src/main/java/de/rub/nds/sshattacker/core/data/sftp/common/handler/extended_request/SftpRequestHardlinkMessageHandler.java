/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestHardlinkMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestHardlinkMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request.SftpRequestHardlinkMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestHardlinkMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestHardlinkMessageHandler
        extends SftpRequestMessageHandler<SftpRequestHardlinkMessage> {

    @Override
    public SftpRequestHardlinkMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestHardlinkMessageParser(array);
    }

    @Override
    public SftpRequestHardlinkMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestHardlinkMessageParser(array, startPosition);
    }

    public static final SftpRequestHardlinkMessagePreparator PREPARATOR =
            new SftpRequestHardlinkMessagePreparator();

    public static final SftpRequestHardlinkMessageSerializer SERIALIZER =
            new SftpRequestHardlinkMessageSerializer();
}
