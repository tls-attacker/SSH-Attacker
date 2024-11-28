/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestUsersGroupsByIdMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpIdEntry;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class SftpRequestUsersGroupsByIdMessage
        extends SftpRequestExtendedMessage<SftpRequestUsersGroupsByIdMessage> {

    private ModifiableInteger userIdsLength;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = SftpIdEntry.class, name = "SftpIdEntry"))
    private List<SftpIdEntry> userIds = new ArrayList<>();

    private ModifiableInteger groupIdsLength;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = SftpIdEntry.class, name = "SftpIdEntry"))
    private List<SftpIdEntry> groupIds = new ArrayList<>();

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

    public void setSoftlyUserIdsLength(int userIdsLength, Config config) {
        if (config.getAlwaysPrepareSftpLengthFields()
                || this.userIdsLength == null
                || this.userIdsLength.getOriginalValue() == null) {
            this.userIdsLength =
                    ModifiableVariableFactory.safelySetValue(this.userIdsLength, userIdsLength);
        }
    }

    public List<SftpIdEntry> getUserIds() {
        return userIds;
    }

    public List<ModifiableInteger> getUserIdsDirect() {
        return userIds.stream().map(SftpIdEntry::getId).collect(Collectors.toList());
    }

    public void setUserIds(List<SftpIdEntry> userIds) {
        this.userIds = userIds;
    }

    public void setUserIdsDirect(List<ModifiableInteger> userIds) {
        this.userIds = userIds.stream().map(SftpIdEntry::new).collect(Collectors.toList());
    }

    public void addUserId(int userId) {
        userIds.add(new SftpIdEntry(ModifiableVariableFactory.safelySetValue(null, userId)));
    }

    public void addUserId(ModifiableInteger userId) {
        userIds.add(new SftpIdEntry(userId));
    }

    public void addUserId(SftpIdEntry userId) {
        userIds.add(userId);
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

    public void setSoftlyGroupIdsLength(int groupIdsLength, Config config) {
        if (config.getAlwaysPrepareSftpLengthFields()
                || this.groupIdsLength == null
                || this.groupIdsLength.getOriginalValue() == null) {
            this.groupIdsLength =
                    ModifiableVariableFactory.safelySetValue(this.groupIdsLength, groupIdsLength);
        }
    }

    public List<SftpIdEntry> getGroupIds() {
        return groupIds;
    }

    public List<ModifiableInteger> getGroupIdsDirect() {
        return groupIds.stream().map(SftpIdEntry::getId).collect(Collectors.toList());
    }

    public void setGroupIds(List<SftpIdEntry> groupIds) {
        this.groupIds = groupIds;
    }

    public void setGroupIdsDirect(List<ModifiableInteger> groupIds) {
        this.groupIds = groupIds.stream().map(SftpIdEntry::new).collect(Collectors.toList());
    }

    public void addGroupId(int groupId) {
        groupIds.add(new SftpIdEntry(ModifiableVariableFactory.safelySetValue(null, groupId)));
    }

    public void addGroupId(ModifiableInteger groupId) {
        groupIds.add(new SftpIdEntry(groupId));
    }

    public void addGroupId(SftpIdEntry groupId) {
        groupIds.add(groupId);
    }

    @Override
    public SftpRequestUsersGroupsByIdMessageHandler getHandler(SshContext context) {
        return new SftpRequestUsersGroupsByIdMessageHandler(context, this);
    }
}
