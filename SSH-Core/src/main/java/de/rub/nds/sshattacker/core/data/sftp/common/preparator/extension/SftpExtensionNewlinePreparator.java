/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionNewline;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionNewlinePreparator
        extends SftpAbstractExtensionPreparator<SftpExtensionNewline> {

    public SftpExtensionNewlinePreparator() {
        super(SftpExtension.NEWLINE);
    }

    @Override
    protected void prepareExtensionSpecificContents(SftpExtensionNewline object, Chooser chooser) {
        object.setNewlineSeperator("\n", true);
    }
}
