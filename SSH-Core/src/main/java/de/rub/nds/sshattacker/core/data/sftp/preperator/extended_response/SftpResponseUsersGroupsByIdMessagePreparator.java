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
        if (getObject().getUserNames().isEmpty()) {
            getObject().addUserName("ssh");
            getObject().addUserName("attacker");
        }
        if (getObject().getGroupNames().isEmpty()) {
            getObject().addGroupName("nds");
        }

        getObject()
                .setSoftlyUserNamesLength(
                        getObject().getUserNames().size() * DataFormatConstants.UINT32_SIZE
                                + getObject().getUserNames().stream()
                                        .map(SftpNameEntry::getNameLength)
                                        .mapToInt(ModifiableVariable::getValue)
                                        .sum(),
                        chooser.getConfig());

        getObject()
                .setSoftlyGroupNamesLength(
                        getObject().getGroupNames().size() * DataFormatConstants.UINT32_SIZE
                                + getObject().getGroupNames().stream()
                                        .map(SftpNameEntry::getNameLength)
                                        .mapToInt(ModifiableVariable::getValue)
                                        .sum(),
                        chooser.getConfig());
    }
}
