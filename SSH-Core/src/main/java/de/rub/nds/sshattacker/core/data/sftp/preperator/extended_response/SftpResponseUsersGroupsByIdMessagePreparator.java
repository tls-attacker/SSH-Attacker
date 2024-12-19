/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseUsersGroupsByIdMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseUsersGroupsByIdMessage> {

    public SftpResponseUsersGroupsByIdMessagePreparator(
            Chooser chooser, SftpResponseUsersGroupsByIdMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareResponseSpecificContents() {
        if (object.getUserNames().isEmpty()) {
            object.addUserName("ssh");
            object.addUserName("attacker");
        }
        if (object.getGroupNames().isEmpty()) {
            object.addGroupName("nds");
        }

        object.setSoftlyUserNamesLength(
                object.getUserNames().size() * DataFormatConstants.UINT32_SIZE
                        + object.getUserNames().stream()
                                .map(SftpNameEntry::getNameLength)
                                .mapToInt(ModifiableVariable::getValue)
                                .sum(),
                config);

        object.setSoftlyGroupNamesLength(
                object.getGroupNames().size() * DataFormatConstants.UINT32_SIZE
                        + object.getGroupNames().stream()
                                .map(SftpNameEntry::getNameLength)
                                .mapToInt(ModifiableVariable::getValue)
                                .sum(),
                config);
    }
}
