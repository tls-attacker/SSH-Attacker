/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpNameEntryPreparator extends Preparator<SftpNameEntry> {

    public SftpNameEntryPreparator(Chooser chooser, SftpNameEntry nameEntry) {
        super(chooser, nameEntry);
    }

    @Override
    public final void prepare() {
        getObject().setSoftlyName("ssh-attacker", true, chooser.getConfig());
    }
}
