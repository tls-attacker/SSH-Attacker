/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpIdEntry;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpIdEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.holder.SftpIdEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.holder.SftpIdEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpIdEntryHandler implements Handler<SftpIdEntry> {

    @Override
    public void adjustContext(SshContext context, SftpIdEntry object) {}

    @Override
    public SftpIdEntryParser getParser(byte[] array, SshContext context) {
        return new SftpIdEntryParser(array);
    }

    @Override
    public SftpIdEntryParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpIdEntryParser(array, startPosition);
    }

    public static final SftpIdEntryPreparator PREPARATOR = new SftpIdEntryPreparator();

    public static final SftpIdEntrySerializer SERIALIZER = new SftpIdEntrySerializer();
}
