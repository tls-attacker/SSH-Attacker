/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpAbstractExtension;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SftpAbstractExtensionPreparator<E extends SftpAbstractExtension<E>>
        extends Preparator<E> {

    protected SftpAbstractExtensionPreparator(Chooser chooser, E extension) {
        super(chooser, extension);
    }

    @Override
    public void prepare() {
        prepareExtensionSpecificContents();
    }

    protected abstract void prepareExtensionSpecificContents();
}
