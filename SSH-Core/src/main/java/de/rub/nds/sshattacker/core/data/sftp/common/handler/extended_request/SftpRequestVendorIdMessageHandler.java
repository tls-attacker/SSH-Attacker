/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestVendorIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestVendorIdMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request.SftpRequestVendorIdMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestVendorIdMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestVendorIdMessageHandler
        extends SftpRequestMessageHandler<SftpRequestVendorIdMessage> {

    @Override
    public SftpRequestVendorIdMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestVendorIdMessageParser(array);
    }

    @Override
    public SftpRequestVendorIdMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestVendorIdMessageParser(array, startPosition);
    }

    public static final SftpRequestVendorIdMessagePreparator PREPARATOR =
            new SftpRequestVendorIdMessagePreparator();

    public static final SftpRequestVendorIdMessageSerializer SERIALIZER =
            new SftpRequestVendorIdMessageSerializer();
}
