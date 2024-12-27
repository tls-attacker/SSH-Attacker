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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
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
    private ArrayList<SftpNameEntry> userNames = new ArrayList<>();

    private ModifiableInteger groupNamesLength;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = SftpNameEntry.class, name = "SftpNameEntry"))
    private ArrayList<SftpNameEntry> groupNames = new ArrayList<>();

    public SftpResponseUsersGroupsByIdMessage() {
        super();
    }

    public SftpResponseUsersGroupsByIdMessage(SftpResponseUsersGroupsByIdMessage other) {
        super(other);
        userNamesLength = other.userNamesLength != null ? other.userNamesLength.createCopy() : null;
        if (other.userNames != null) {
            userNames = new ArrayList<>(other.userNames.size());
            for (SftpNameEntry item : other.userNames) {
                userNames.add(item != null ? item.createCopy() : null);
            }
        }
        groupNamesLength =
                other.groupNamesLength != null ? other.groupNamesLength.createCopy() : null;
        if (other.groupNames != null) {
            groupNames = new ArrayList<>(other.groupNames.size());
            for (SftpNameEntry item : other.groupNames) {
                groupNames.add(item != null ? item.createCopy() : null);
            }
        }
    }

    @Override
    public SftpResponseUsersGroupsByIdMessage createCopy() {
        return new SftpResponseUsersGroupsByIdMessage(this);
    }

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

    public ArrayList<SftpNameEntry> getUserNames() {
        return userNames;
    }

    public List<ModifiableString> getUserNamesDirect() {
        return userNames.stream().map(SftpNameEntry::getName).collect(Collectors.toList());
    }

    public void setUserNames(ArrayList<SftpNameEntry> userNames) {
        this.userNames = userNames;
    }

    public void setUserNamesDirect(List<ModifiableString> userNames) {
        this.userNames =
                userNames.stream()
                        .map(SftpNameEntry::new)
                        .collect(Collectors.toCollection(ArrayList::new));
    }

    public void addUserName(SftpNameEntry userName) {
        userNames.add(userName);
    }

    public void addUserName(ModifiableString userName) {
        userNames.add(new SftpNameEntry(userName));
    }

    public void addUserName(String userName) {
        userNames.add(new SftpNameEntry(new ModifiableString(userName)));
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

    public ArrayList<SftpNameEntry> getGroupNames() {
        return groupNames;
    }

    public List<ModifiableString> getGroupNamesDirect() {
        return groupNames.stream().map(SftpNameEntry::getName).collect(Collectors.toList());
    }

    public void setGroupNames(ArrayList<SftpNameEntry> groupNames) {
        this.groupNames = groupNames;
    }

    public void setGroupNamesDirect(List<ModifiableString> groupNames) {
        this.groupNames =
                groupNames.stream()
                        .map(SftpNameEntry::new)
                        .collect(Collectors.toCollection(ArrayList::new));
    }

    public void addGroupName(SftpNameEntry groupName) {
        groupNames.add(groupName);
    }

    public void addGroupName(ModifiableString groupName) {
        groupNames.add(new SftpNameEntry(groupName));
    }

    public void addGroupName(String groupName) {
        groupNames.add(new SftpNameEntry(new ModifiableString(groupName)));
    }

    @Override
    public SftpResponseUsersGroupsByIdMessageHandler getHandler(SshContext context) {
        return new SftpResponseUsersGroupsByIdMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpResponseUsersGroupsByIdMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpResponseUsersGroupsByIdMessageHandler.SERIALIZER.serialize(this);
    }
}
