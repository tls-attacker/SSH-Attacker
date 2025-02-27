/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestExtendedMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.request.SftpRequestMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SftpRequestExtendedMessagePreparator<T extends SftpRequestExtendedMessage<T>>
        extends SftpRequestMessagePreparator<T> {

    private final String extendedRequestName;

    protected SftpRequestExtendedMessagePreparator(SftpExtension extendedRequestName) {
        this(extendedRequestName.getName());
    }

    protected SftpRequestExtendedMessagePreparator(String extendedRequestName) {
        super(SftpPacketTypeConstant.SSH_FXP_EXTENDED);
        this.extendedRequestName = extendedRequestName;
    }

    @Override
    public void prepareRequestSpecificContents(T object, Chooser chooser) {
        // Always set correct extended request name -> Don't use soft set
        object.setExtendedRequestName(extendedRequestName, true);
        prepareRequestExtendedSpecificContents(object, chooser);
    }

    protected abstract void prepareRequestExtendedSpecificContents(T object, Chooser chooser);
}
