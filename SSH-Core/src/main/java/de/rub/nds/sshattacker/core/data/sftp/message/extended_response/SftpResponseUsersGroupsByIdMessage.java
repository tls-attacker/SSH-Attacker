/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_response.SftpResponseUsersGroupsByIdMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.ArrayList;
import java.util.List;

public class SftpResponseUsersGroupsByIdMessage
        extends SftpResponseMessage<SftpResponseUsersGroupsByIdMessage> {

    private ModifiableInteger userNamesLength;
    private List<ModifiableString> userNames = new ArrayList<>();
    private ModifiableInteger groupNamesLength;
    private List<ModifiableString> groupNames = new ArrayList<>();

    public ModifiableInteger getUserNamesLength() {
        return userNamesLength;
    }

    public void setUserNamesLength(ModifiableInteger userNamesLength) {
        this.userNamesLength = userNamesLength;
    }

    public void setUserNamesLength(int userNamesLength) {
        this.userNamesLength =
                ModifiableVariableFactory.safelySetValue(this.userNamesLength, userNamesLength);
    }

    public List<ModifiableString> getUserNames() {
        return userNames;
    }

    public void setUserNames(List<ModifiableString> userNames) {
        this.userNames = userNames;
    }

    public void addUserName(ModifiableString userName) {
        userNames.add(userName);
    }

    public void addUserName(String userName) {
        userNames.add(ModifiableVariableFactory.safelySetValue(null, userName));
    }

    public ModifiableInteger getGroupNamesLength() {
        return groupNamesLength;
    }

    public void setGroupNamesLength(ModifiableInteger groupNamesLength) {
        this.groupNamesLength = groupNamesLength;
    }

    public void setGroupNamesLength(int groupNamesLength) {
        this.groupNamesLength =
                ModifiableVariableFactory.safelySetValue(this.groupNamesLength, groupNamesLength);
    }

    public List<ModifiableString> getGroupNames() {
        return groupNames;
    }

    public void setGroupNames(List<ModifiableString> groupNames) {
        this.groupNames = groupNames;
    }

    public void addGroupName(ModifiableString groupName) {
        groupNames.add(groupName);
    }

    public void addGroupName(String groupName) {
        groupNames.add(ModifiableVariableFactory.safelySetValue(null, groupName));
    }

    @Override
    public SftpResponseUsersGroupsByIdMessageHandler getHandler(SshContext context) {
        return new SftpResponseUsersGroupsByIdMessageHandler(context, this);
    }
}
