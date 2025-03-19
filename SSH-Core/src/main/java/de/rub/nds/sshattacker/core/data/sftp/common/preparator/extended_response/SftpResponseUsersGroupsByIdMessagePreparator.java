/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_response;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseUsersGroupsByIdMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseUsersGroupsByIdMessage> {

    @Override
    public void prepareResponseSpecificContents(
            SftpResponseUsersGroupsByIdMessage object, Chooser chooser) {
        if (object.getUserNames().isEmpty()) {
            object.addUserName("ssh");
            object.addUserName("attacker");
        } else {
            object.getUserNames().forEach(userName -> userName.prepare(chooser));
        }
        if (object.getGroupNames().isEmpty()) {
            object.addGroupName("nds");
        } else {
            object.getGroupNames().forEach(groupName -> groupName.prepare(chooser));
        }

        object.setUserNamesLength(
                object.getUserNames().size() * DataFormatConstants.UINT32_SIZE
                        + object.getUserNames().stream()
                                .map(SftpNameEntry::getNameLength)
                                .mapToInt(ModifiableVariable::getValue)
                                .sum());

        object.setGroupNamesLength(
                object.getGroupNames().size() * DataFormatConstants.UINT32_SIZE
                        + object.getGroupNames().stream()
                                .map(SftpNameEntry::getNameLength)
                                .mapToInt(ModifiableVariable::getValue)
                                .sum());
    }
}
