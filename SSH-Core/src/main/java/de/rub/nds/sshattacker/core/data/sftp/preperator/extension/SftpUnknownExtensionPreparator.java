/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpUnknownExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpUnknownExtensionPreparator
        extends SftpAbstractExtensionPreparator<SftpUnknownExtension> {

    public SftpUnknownExtensionPreparator(Chooser chooser, SftpUnknownExtension extension) {
        super(chooser, extension);
    }

    @Override
    protected void prepareExtensionSpecificContents() {
        if (getObject().getName() == null) {
            getObject().setName("hello-from@ssh-attacker", true);
        }
        if (getObject().getNameLength() == null) {
            getObject().setNameLength(getObject().getName().getValue().length());
        }

        if (getObject().getValue() == null) {
            getObject().setValue(new byte[100], true);
        }
        if (getObject().getValueLength() == null) {
            getObject().setValueLength(getObject().getValue().getValue().length);
        }
    }
}
