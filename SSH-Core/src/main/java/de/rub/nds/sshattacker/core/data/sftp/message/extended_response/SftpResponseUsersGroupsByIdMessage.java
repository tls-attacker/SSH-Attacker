/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_response;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_response.SftpResponseUsersGroupsByIdMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class SftpResponseUsersGroupsByIdMessage
        extends SftpResponseMessage<SftpResponseUsersGroupsByIdMessage> {

    private ModifiableInteger userNamesLength;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = SftpNameEntry.class, name = "SftpNameEntry"))
    private List<SftpNameEntry> userNames = new ArrayList<>();

    private ModifiableInteger groupNamesLength;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = SftpNameEntry.class, name = "SftpNameEntry"))
    private List<SftpNameEntry> groupNames = new ArrayList<>();

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

    public void setSoftlyUserNamesLength(int userNamesLength, Config config) {
        if (config.getAlwaysPrepareSftpLengthFields()
                || this.userNamesLength == null
                || this.userNamesLength.getOriginalValue() == null) {
            this.userNamesLength =
                    ModifiableVariableFactory.safelySetValue(this.userNamesLength, userNamesLength);
        }
    }

    public List<SftpNameEntry> getUserNames() {
        return userNames;
    }

    public List<ModifiableString> getUserNamesDirect() {
        return userNames.stream().map(SftpNameEntry::getName).collect(Collectors.toList());
    }

    public void setUserNames(List<SftpNameEntry> userNames) {
        this.userNames = userNames;
    }

    public void setUserNamesDirect(List<ModifiableString> userNames) {
        this.userNames = userNames.stream().map(SftpNameEntry::new).collect(Collectors.toList());
        ;
    }

    public void addUserName(SftpNameEntry userName) {
        userNames.add(userName);
    }

    public void addUserName(ModifiableString userName) {
        userNames.add(new SftpNameEntry(userName));
    }

    public void addUserName(String userName) {
        userNames.add(new SftpNameEntry(ModifiableVariableFactory.safelySetValue(null, userName)));
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

    public void setSoftlyGroupNamesLength(int groupNamesLength, Config config) {
        if (config.getAlwaysPrepareSftpLengthFields()
                || this.groupNamesLength == null
                || this.groupNamesLength.getOriginalValue() == null) {
            this.groupNamesLength =
                    ModifiableVariableFactory.safelySetValue(
                            this.groupNamesLength, groupNamesLength);
        }
    }

    public List<SftpNameEntry> getGroupNames() {
        return groupNames;
    }

    public List<ModifiableString> getGroupNamesDirect() {
        return groupNames.stream().map(SftpNameEntry::getName).collect(Collectors.toList());
    }

    public void setGroupNames(List<SftpNameEntry> groupNames) {
        this.groupNames = groupNames;
    }

    public void setGroupNamesDirect(List<ModifiableString> groupNames) {
        this.groupNames = groupNames.stream().map(SftpNameEntry::new).collect(Collectors.toList());
        ;
        ;
    }

    public void addGroupName(SftpNameEntry groupName) {
        groupNames.add(groupName);
    }

    public void addGroupName(ModifiableString groupName) {
        groupNames.add(new SftpNameEntry(groupName));
    }

    public void addGroupName(String groupName) {
        groupNames.add(
                new SftpNameEntry(ModifiableVariableFactory.safelySetValue(null, groupName)));
    }

    @Override
    public SftpResponseUsersGroupsByIdMessageHandler getHandler(SshContext context) {
        return new SftpResponseUsersGroupsByIdMessageHandler(context, this);
    }
}
