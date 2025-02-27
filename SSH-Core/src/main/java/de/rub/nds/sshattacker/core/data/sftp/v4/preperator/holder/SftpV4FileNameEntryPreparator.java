/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.preperator.holder;

import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4FileNameEntryPreparator extends Preparator<SftpV4FileNameEntry> {

    @Override
    public final void prepare(SftpV4FileNameEntry object, Chooser chooser) {
        object.setFilename("/etc/passwd", true);
        object.getAttributes().prepare(chooser);
    }
}
