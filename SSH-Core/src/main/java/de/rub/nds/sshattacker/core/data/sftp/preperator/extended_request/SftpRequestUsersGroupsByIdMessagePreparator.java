/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestUsersGroupsByIdMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestUsersGroupsByIdMessage> {

    public SftpRequestUsersGroupsByIdMessagePreparator(
            Chooser chooser, SftpRequestUsersGroupsByIdMessage message) {
        super(chooser, message, SftpExtension.USERS_GROUPS_BY_ID);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        if (getObject().getUserIds().isEmpty()) {
            getObject().addUserId(0);
            getObject().addUserId(1000);
        }
        if (getObject().getGroupIds().isEmpty()) {
            getObject().addGroupId(0);
        }
        getObject()
                .setUserIdsLength(
                        getObject().getUserIds().size() * DataFormatConstants.UINT32_SIZE);
        getObject()
                .setGroupIdsLength(
                        getObject().getGroupIds().size() * DataFormatConstants.UINT32_SIZE);
    }
}
