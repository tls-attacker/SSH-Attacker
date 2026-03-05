/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileNameEntry;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.holder.SftpV4FileNameEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preparator.holder.SftpV4FileNameEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.holder.SftpV4FileNameEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4FileNameEntryHandler implements Handler<SftpV4FileNameEntry> {

    @Override
    public void adjustContext(SshContext context, SftpV4FileNameEntry object) {}

    @Override
    public SftpV4FileNameEntryParser getParser(byte[] array, SshContext context) {
        return new SftpV4FileNameEntryParser(array);
    }

    @Override
    public SftpV4FileNameEntryParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4FileNameEntryParser(array, startPosition);
    }

    public static final SftpV4FileNameEntryPreparator PREPARATOR =
            new SftpV4FileNameEntryPreparator();

    public static final SftpV4FileNameEntrySerializer SERIALIZER =
            new SftpV4FileNameEntrySerializer();
}
