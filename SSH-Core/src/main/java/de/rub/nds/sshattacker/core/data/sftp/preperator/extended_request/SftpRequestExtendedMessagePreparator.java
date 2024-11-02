/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestExtendedMessage;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SftpRequestExtendedMessagePreparator<T extends SftpRequestExtendedMessage<T>>
        extends SftpRequestMessagePreparator<T> {

    private final String extendedRequestName;

    protected SftpRequestExtendedMessagePreparator(
            Chooser chooser, T message, SftpExtension extendedRequestName) {
        this(chooser, message, extendedRequestName.getName());
    }

    protected SftpRequestExtendedMessagePreparator(
            Chooser chooser, T message, String extendedRequestName) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_EXTENDED);
        this.extendedRequestName = extendedRequestName;
    }

    @Override
    public void prepareRequestSpecificContents() {
        getObject().setExtendedRequestName(extendedRequestName, true);
        prepareRequestExtendedSpecificContents();
    }

    protected abstract void prepareRequestExtendedSpecificContents();
}
