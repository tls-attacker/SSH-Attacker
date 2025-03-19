/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.holder.SftpV4FileAttributesParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preparator.holder.SftpV4FileAttributesPreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.holder.SftpV4FileAttributesSerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4FileAttributesHandler implements Handler<SftpV4FileAttributes> {

    @Override
    public void adjustContext(SshContext context, SftpV4FileAttributes object) {}

    @Override
    public SftpV4FileAttributesParser getParser(byte[] array, SshContext context) {
        return new SftpV4FileAttributesParser(array);
    }

    @Override
    public SftpV4FileAttributesParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4FileAttributesParser(array, startPosition);
    }

    public static final SftpV4FileAttributesPreparator PREPARATOR =
            new SftpV4FileAttributesPreparator();

    public static final SftpV4FileAttributesSerializer SERIALIZER =
            new SftpV4FileAttributesSerializer();
}
