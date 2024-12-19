/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionUnknown;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionUnknownPreparator
        extends SftpAbstractExtensionPreparator<SftpExtensionUnknown> {

    public SftpExtensionUnknownPreparator(Chooser chooser, SftpExtensionUnknown extension) {
        super(chooser, extension, "hello-from@ssh-attacker.de");
    }

    @Override
    public void prepareExtensionSpecificContents() {
        object.setSoftlyValue(new byte[100], true, config);
    }
}
