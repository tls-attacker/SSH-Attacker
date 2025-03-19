/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpNameEntryPreparator extends Preparator<SftpNameEntry> {

    @Override
    public final void prepare(SftpNameEntry object, Chooser chooser) {
        object.setName("ssh-attacker", true);
    }
}
