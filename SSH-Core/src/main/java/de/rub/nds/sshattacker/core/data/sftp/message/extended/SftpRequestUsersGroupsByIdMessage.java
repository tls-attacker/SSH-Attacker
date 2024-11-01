/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended.SftpRequestUsersGroupsByIdMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.ArrayList;
import java.util.List;

public class SftpRequestUsersGroupsByIdMessage
        extends SftpRequestExtendedMessage<SftpRequestUsersGroupsByIdMessage> {

    private ModifiableInteger userIdsLength;
    private List<ModifiableInteger> userIds = new ArrayList<>();
    private ModifiableInteger groupIdsLength;
    private List<ModifiableInteger> groupIds = new ArrayList<>();

    public ModifiableInteger getUserIdsLength() {
        return userIdsLength;
    }

    public void setUserIdsLength(ModifiableInteger userIdsLength) {
        this.userIdsLength = userIdsLength;
    }

    public void setUserIdsLength(int userIdsLength) {
        this.userIdsLength =
                ModifiableVariableFactory.safelySetValue(this.userIdsLength, userIdsLength);
    }

    public ModifiableInteger getGroupIdsLength() {
        return groupIdsLength;
    }

    public void setGroupIdsLength(ModifiableInteger groupIdsLength) {
        this.groupIdsLength = groupIdsLength;
    }

    public void setGroupIdsLength(int groupIdsLength) {
        this.groupIdsLength =
                ModifiableVariableFactory.safelySetValue(this.groupIdsLength, groupIdsLength);
    }

    public List<ModifiableInteger> getUserIds() {
        return userIds;
    }

    public void setUserIds(List<ModifiableInteger> userIds) {
        this.userIds = userIds;
    }

    public void addUserId(int userId) {
        userIds.add(ModifiableVariableFactory.safelySetValue(null, userId));
    }

    public void addUserId(ModifiableInteger userId) {
        userIds.add(userId);
    }

    public List<ModifiableInteger> getGroupIds() {
        return groupIds;
    }

    public void setGroupIds(List<ModifiableInteger> groupIds) {
        this.groupIds = groupIds;
    }

    public void addGroupId(int groupId) {
        groupIds.add(ModifiableVariableFactory.safelySetValue(null, groupId));
    }

    public void addGroupId(ModifiableInteger groupId) {
        groupIds.add(groupId);
    }

    @Override
    public SftpRequestUsersGroupsByIdMessageHandler getHandler(SshContext context) {
        return new SftpRequestUsersGroupsByIdMessageHandler(context);
    }
}
