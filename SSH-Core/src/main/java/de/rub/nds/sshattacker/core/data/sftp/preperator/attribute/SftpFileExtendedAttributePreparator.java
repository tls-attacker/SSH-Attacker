/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.attribute;

import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpFileExtendedAttributePreparator extends Preparator<SftpFileExtendedAttribute> {

    public SftpFileExtendedAttributePreparator(
            Chooser chooser, SftpFileExtendedAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public final void prepare() {
        if(getObject().getType() == null){
            getObject().setType("hello-from@ssh-attacker", true);
        }
        if(getObject().getTypeLength() == null){
            getObject().setTypeLength(getObject().getType().getValue().length());
        }

        if(getObject().getData() == null) {
            getObject().setData(new byte[100], true);
        }
        if(getObject().getDataLength() == null){
            getObject().setDataLength(getObject().getData().getValue().length);
        }
    }
}
