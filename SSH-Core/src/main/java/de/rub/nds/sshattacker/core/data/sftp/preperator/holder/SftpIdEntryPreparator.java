/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpIdEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpIdEntryPreparator extends Preparator<SftpIdEntry> {

    public SftpIdEntryPreparator(Chooser chooser, SftpIdEntry idEntry) {
        super(chooser, idEntry);
    }

    @Override
    public final void prepare() {
        if (getObject().getId() == null) {
            getObject().setId(1000);
        }
    }
}
