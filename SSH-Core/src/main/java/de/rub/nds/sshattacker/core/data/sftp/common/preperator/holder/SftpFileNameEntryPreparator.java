/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.holder;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpFileNameEntryPreparator extends Preparator<SftpFileNameEntry> {

    @Override
    public final void prepare(SftpFileNameEntry object, Chooser chooser) {
        Config config = chooser.getConfig();
        object.setFilename("/etc/passwd", true);
        object.setLongName("-rwxr-xr-x   1 ssh      attacker   348911 Mar 25 14:29 passwd", true);

        object.getAttributes().prepare(chooser);
    }
}
