/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpFileAttributesParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.holder.SftpFileAttributesPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.holder.SftpFileAttributesSerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpFileAttributesHandler implements Handler<SftpFileAttributes> {

    @Override
    public void adjustContext(SshContext context, SftpFileAttributes object) {}

    @Override
    public SftpFileAttributesParser getParser(byte[] array, SshContext context) {
        return new SftpFileAttributesParser(array);
    }

    @Override
    public SftpFileAttributesParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpFileAttributesParser(array, startPosition);
    }

    public static final SftpFileAttributesPreparator PREPARATOR =
            new SftpFileAttributesPreparator();

    public static final SftpFileAttributesSerializer SERIALIZER =
            new SftpFileAttributesSerializer();
}
