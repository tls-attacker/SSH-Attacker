/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionNewline;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionNewlinePreparator
        extends SftpAbstractExtensionPreparator<SftpExtensionNewline> {

    public SftpExtensionNewlinePreparator(Chooser chooser, SftpExtensionNewline extension) {
        super(chooser, extension, SftpExtension.NEWLINE);
    }

    @Override
    public void prepareExtensionSpecificContents() {
        getObject().setSoftlyNewlineSeperator("\n", true, chooser.getConfig());
    }
}
