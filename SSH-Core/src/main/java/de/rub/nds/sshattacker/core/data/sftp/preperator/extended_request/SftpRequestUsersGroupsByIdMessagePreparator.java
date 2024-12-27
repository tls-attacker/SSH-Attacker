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

    public SftpRequestUsersGroupsByIdMessagePreparator() {
        super(SftpExtension.USERS_GROUPS_BY_ID);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestUsersGroupsByIdMessage object, Chooser chooser) {
        if (object.getUserIds().isEmpty()) {
            object.addUserId(0);
            object.addUserId(1000);
        } else {
            object.getUserIds().forEach(userId -> userId.prepare(chooser));
        }
        if (object.getGroupIds().isEmpty()) {
            object.addGroupId(0);
        } else {
            object.getGroupIds().forEach(groupId -> groupId.prepare(chooser));
        }

        object.setSoftlyUserIdsLength(
                object.getUserIds().size() * DataFormatConstants.UINT32_SIZE, chooser.getConfig());

        object.setSoftlyGroupIdsLength(
                object.getGroupIds().size() * DataFormatConstants.UINT32_SIZE, chooser.getConfig());
    }
}
