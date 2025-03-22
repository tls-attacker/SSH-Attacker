/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpNameEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.holder.SftpNameEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.holder.SftpNameEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpNameEntryHandler implements Handler<SftpNameEntry> {

    @Override
    public void adjustContext(SshContext context, SftpNameEntry object) {}

    @Override
    public SftpNameEntryParser getParser(byte[] array, SshContext context) {
        return new SftpNameEntryParser(array);
    }

    @Override
    public SftpNameEntryParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpNameEntryParser(array, startPosition);
    }

    public static final SftpNameEntryPreparator PREPARATOR = new SftpNameEntryPreparator();

    public static final SftpNameEntrySerializer SERIALIZER = new SftpNameEntrySerializer();
}
