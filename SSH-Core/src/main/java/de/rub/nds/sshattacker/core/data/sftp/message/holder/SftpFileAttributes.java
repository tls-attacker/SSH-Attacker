/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.holder;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.constants.SftpFileType;
import de.rub.nds.sshattacker.core.data.sftp.handler.holder.SftpFileAttributesHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
public class SftpFileAttributes extends ModifiableVariableHolder {

    private ModifiableInteger flags;
    private ModifiableLong size;
    private ModifiableInteger userId;
    private ModifiableInteger groupId;
    private ModifiableInteger permissions;
    private ModifiableInteger accessTime;
    private ModifiableInteger modifyTime;
    private ModifiableInteger extendedCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            @XmlElement(type = SftpFileExtendedAttribute.class, name = "SftpFileExtendedAttribute"))
    private List<SftpFileExtendedAttribute> extendedAttributes = new ArrayList<>();

    // SFTP V4

    private ModifiableByte type;

    private ModifiableInteger ownerLength;
    private ModifiableString owner;
    private ModifiableInteger groupLength;
    private ModifiableString group;

    private ModifiableInteger createTime;

    private ModifiableInteger aclLength;
    private ModifiableInteger aclEntriesCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = SftpAclEntry.class, name = "SftpAclEntry"))
    private List<SftpAclEntry> aclEntries = new ArrayList<>();

    public ModifiableInteger getFlags() {
        return flags;
    }

    public void setFlags(ModifiableInteger flags) {
        this.flags = flags;
    }

    public void setFlags(int flags) {
        this.flags = ModifiableVariableFactory.safelySetValue(this.flags, flags);
    }

    public void setFlags(SftpFileAttributeFlag... attributeFlags) {
        setFlags(SftpFileAttributeFlag.flagsToInt(attributeFlags));
    }

    public ModifiableLong getSize() {
        return size;
    }

    public void setSize(ModifiableLong size) {
        this.size = size;
    }

    public void setSize(long size) {
        this.size = ModifiableVariableFactory.safelySetValue(this.size, size);
    }

    public void clearSize() {
        size = null;
    }

    public ModifiableInteger getUserId() {
        return userId;
    }

    public void setUserId(ModifiableInteger userId) {
        this.userId = userId;
    }

    public void setUserId(int userId) {
        this.userId = ModifiableVariableFactory.safelySetValue(this.userId, userId);
    }

    public void clearUserId() {
        userId = null;
    }

    public ModifiableInteger getGroupId() {
        return groupId;
    }

    public void setGroupId(ModifiableInteger groupId) {
        this.groupId = groupId;
    }

    public void setGroupId(int groupId) {
        this.groupId = ModifiableVariableFactory.safelySetValue(this.groupId, groupId);
    }

    public void clearGroupId() {
        groupId = null;
    }

    public ModifiableInteger getPermissions() {
        return permissions;
    }

    public void setPermissions(ModifiableInteger permissions) {
        this.permissions = permissions;
    }

    public void setPermissions(int permissions) {
        this.permissions = ModifiableVariableFactory.safelySetValue(this.permissions, permissions);
    }

    public void clearPermissions() {
        permissions = null;
    }

    public ModifiableInteger getAccessTime() {
        return accessTime;
    }

    public void setAccessTime(ModifiableInteger accessTime) {
        this.accessTime = accessTime;
    }

    public void setAccessTime(int accessTime) {
        this.accessTime = ModifiableVariableFactory.safelySetValue(this.accessTime, accessTime);
    }

    public void clearAccessTime() {
        accessTime = null;
    }

    public ModifiableInteger getModifyTime() {
        return modifyTime;
    }

    public void setModifyTime(ModifiableInteger modifyTime) {
        this.modifyTime = modifyTime;
    }

    public void setModifyTime(int modifyTime) {
        this.modifyTime = ModifiableVariableFactory.safelySetValue(this.modifyTime, modifyTime);
    }

    public void clearModifyTime() {
        modifyTime = null;
    }

    public ModifiableInteger getExtendedCount() {
        return extendedCount;
    }

    public void setExtendedCount(ModifiableInteger extendedCount) {
        this.extendedCount = extendedCount;
    }

    public void setExtendedCount(int extendedCount) {
        this.extendedCount =
                ModifiableVariableFactory.safelySetValue(this.extendedCount, extendedCount);
    }

    public void clearExtendedAttributes() {
        extendedCount = null;
        extendedAttributes = new ArrayList<>();
    }

    public List<SftpFileExtendedAttribute> getExtendedAttributes() {
        return extendedAttributes;
    }

    public void setExtendedAttributes(List<SftpFileExtendedAttribute> extendedAttributes) {
        setExtendedAttributes(extendedAttributes, false);
    }

    public void setExtendedAttributes(
            List<SftpFileExtendedAttribute> extendedAttributes, boolean adjustLengthField) {
        if (adjustLengthField) {
            setExtendedCount(extendedAttributes.size());
        }
        this.extendedAttributes = extendedAttributes;
    }

    public void addExtendedAttribute(SftpFileExtendedAttribute extendedAttribute) {
        addExtendedAttribute(extendedAttribute, false);
    }

    public void addExtendedAttribute(
            SftpFileExtendedAttribute extendedAttribute, boolean adjustLengthField) {
        extendedAttributes.add(extendedAttribute);
        if (adjustLengthField) {
            setExtendedCount(extendedAttributes.size());
        }
    }

    public SftpFileAttributesHandler getHandler(SshContext context) {
        return new SftpFileAttributesHandler(context, this);
    }

    // SFTP v4

    public ModifiableByte getType() {
        return type;
    }

    public void setType(ModifiableByte type) {
        this.type = type;
    }

    public void setType(byte type) {
        this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
    }

    public void setType(SftpFileType type) {
        setType(type.getType());
    }

    public void clearType() {
        type = null;
    }

    public ModifiableInteger getOwnerLength() {
        return ownerLength;
    }

    public void setOwnerLength(ModifiableInteger ownerLength) {
        this.ownerLength = ownerLength;
    }

    public void setOwnerLength(int ownerLength) {
        this.ownerLength = ModifiableVariableFactory.safelySetValue(this.ownerLength, ownerLength);
    }

    public ModifiableString getOwner() {
        return owner;
    }

    public void setOwner(ModifiableString owner) {
        setOwner(owner, false);
    }

    public void setOwner(String owner) {
        setOwner(owner, false);
    }

    public void setOwner(ModifiableString owner, boolean adjustLengthField) {
        if (adjustLengthField) {
            setOwnerLength(owner.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.owner = owner;
    }

    public void setOwner(String owner, boolean adjustLengthField) {
        if (adjustLengthField) {
            setOwnerLength(owner.getBytes(StandardCharsets.UTF_8).length);
        }
        this.owner = ModifiableVariableFactory.safelySetValue(this.owner, owner);
    }

    public void clearOwner() {
        ownerLength = null;
        owner = null;
    }

    public ModifiableInteger getGroupLength() {
        return groupLength;
    }

    public void setGroupLength(ModifiableInteger groupLength) {
        this.groupLength = groupLength;
    }

    public void setGroupLength(int groupLength) {
        this.groupLength = ModifiableVariableFactory.safelySetValue(this.groupLength, groupLength);
    }

    public ModifiableString getGroup() {
        return group;
    }

    public void setGroup(ModifiableString group) {
        setGroup(group, false);
    }

    public void setGroup(String group) {
        setGroup(group, false);
    }

    public void setGroup(ModifiableString group, boolean adjustLengthField) {
        if (adjustLengthField) {
            setGroupLength(group.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.group = group;
    }

    public void setGroup(String group, boolean adjustLengthField) {
        if (adjustLengthField) {
            setGroupLength(group.getBytes(StandardCharsets.UTF_8).length);
        }
        this.group = ModifiableVariableFactory.safelySetValue(this.group, group);
    }

    public void clearGroup() {
        groupLength = null;
        group = null;
    }

    public ModifiableInteger getCreateTime() {
        return createTime;
    }

    public void setCreateTime(ModifiableInteger createTime) {
        this.createTime = createTime;
    }

    public void setCreateTime(int createTime) {
        this.createTime = ModifiableVariableFactory.safelySetValue(this.createTime, createTime);
    }

    public void clearCreateTime() {
        createTime = null;
    }

    public ModifiableInteger getAclLength() {
        return aclLength;
    }

    public void clearAcl() {
        aclLength = null;
        aclEntriesCount = null;
        aclEntries = new ArrayList<>();
    }

    public void setAclLength(ModifiableInteger aclLength) {
        this.aclLength = aclLength;
    }

    public void setAclLength(int aclLength) {
        this.aclLength = ModifiableVariableFactory.safelySetValue(this.aclLength, aclLength);
    }

    public ModifiableInteger getAclEntriesCount() {
        return aclEntriesCount;
    }

    public void setAclEntriesCount(ModifiableInteger aclEntriesCount) {
        this.aclEntriesCount = aclEntriesCount;
    }

    public void setAclEntriesCount(int aclEntriesCount) {
        this.aclEntriesCount =
                ModifiableVariableFactory.safelySetValue(this.aclEntriesCount, aclEntriesCount);
    }

    public List<SftpAclEntry> getAclEntries() {
        return aclEntries;
    }

    public void setAclEntries(List<SftpAclEntry> aclEntries) {
        setAclEntries(aclEntries, false);
    }

    public void setAclEntries(List<SftpAclEntry> aclEntries, boolean adjustLengthField) {
        if (adjustLengthField) {
            setAclEntriesCount(aclEntries.size());
        }
        this.aclEntries = aclEntries;
    }

    public void addAclEntry(SftpAclEntry aclEntry) {
        addAclEntry(aclEntry, false);
    }

    public void addAclEntry(SftpAclEntry aclEntry, boolean adjustLengthField) {
        aclEntries.add(aclEntry);
        if (adjustLengthField) {
            setAclEntriesCount(aclEntries.size());
        }
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        holders.addAll(extendedAttributes);
        holders.addAll(aclEntries);
        return holders;
    }
}
