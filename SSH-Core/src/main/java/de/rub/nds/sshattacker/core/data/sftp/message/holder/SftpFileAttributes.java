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
import de.rub.nds.sshattacker.core.config.Config;
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
    private ArrayList<SftpFileExtendedAttribute> extendedAttributes = new ArrayList<>();

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
    private ArrayList<SftpAclEntry> aclEntries = new ArrayList<>();

    public SftpFileAttributes() {
        super();
    }

    public SftpFileAttributes(SftpFileAttributes other) {
        super(other);
        flags = other.flags != null ? other.flags.createCopy() : null;
        size = other.size != null ? other.size.createCopy() : null;
        userId = other.userId != null ? other.userId.createCopy() : null;
        groupId = other.groupId != null ? other.groupId.createCopy() : null;
        permissions = other.permissions != null ? other.permissions.createCopy() : null;
        accessTime = other.accessTime != null ? other.accessTime.createCopy() : null;
        modifyTime = other.modifyTime != null ? other.modifyTime.createCopy() : null;
        extendedCount = other.extendedCount != null ? other.extendedCount.createCopy() : null;
        if (other.extendedAttributes != null) {
            extendedAttributes = new ArrayList<>(other.extendedAttributes.size());
            for (SftpFileExtendedAttribute item : other.extendedAttributes) {
                extendedAttributes.add(item != null ? item.createCopy() : null);
            }
        }
        type = other.type != null ? other.type.createCopy() : null;
        ownerLength = other.ownerLength != null ? other.ownerLength.createCopy() : null;
        owner = other.owner != null ? other.owner.createCopy() : null;
        groupLength = other.groupLength != null ? other.groupLength.createCopy() : null;
        group = other.group != null ? other.group.createCopy() : null;
        createTime = other.createTime != null ? other.createTime.createCopy() : null;
        aclLength = other.aclLength != null ? other.aclLength.createCopy() : null;
        aclEntriesCount = other.aclEntriesCount != null ? other.aclEntriesCount.createCopy() : null;
        if (other.aclEntries != null) {
            aclEntries = new ArrayList<>(other.aclEntries.size());
            for (SftpAclEntry item : other.aclEntries) {
                aclEntries.add(item != null ? item.createCopy() : null);
            }
        }
    }

    @Override
    public SftpFileAttributes createCopy() {
        return new SftpFileAttributes(this);
    }

    public ModifiableInteger getFlags() {
        return flags;
    }

    public void setFlags(ModifiableInteger flags) {
        this.flags = flags;
    }

    public void setFlags(int flags) {
        this.flags = ModifiableVariableFactory.safelySetValue(this.flags, flags);
    }

    public void setSoftlyFlags(int flags) {
        if (this.flags == null || this.flags.getOriginalValue() == null) {
            this.flags = ModifiableVariableFactory.safelySetValue(this.flags, flags);
        }
    }

    public void setFlags(SftpFileAttributeFlag... attributeFlags) {
        setFlags(SftpFileAttributeFlag.flagsToInt(attributeFlags));
    }

    public void setSoftlyFlags(SftpFileAttributeFlag... attributeFlags) {
        if (flags == null || flags.getOriginalValue() == null) {
            setFlags(SftpFileAttributeFlag.flagsToInt(attributeFlags));
        }
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

    public void setSoftlySize(long size) {
        if (this.size == null || this.size.getOriginalValue() == null) {
            this.size = ModifiableVariableFactory.safelySetValue(this.size, size);
        }
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

    public void setSoftlyUserId(int userId) {
        if (this.userId == null || this.userId.getOriginalValue() == null) {
            this.userId = ModifiableVariableFactory.safelySetValue(this.userId, userId);
        }
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

    public void setSoftlyGroupId(int groupId) {
        if (this.groupId == null || this.groupId.getOriginalValue() == null) {
            this.groupId = ModifiableVariableFactory.safelySetValue(this.groupId, groupId);
        }
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

    public void setSoftlyPermissions(int permissions) {
        if (this.permissions == null || this.permissions.getOriginalValue() == null) {
            this.permissions =
                    ModifiableVariableFactory.safelySetValue(this.permissions, permissions);
        }
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

    public void setSoftlyAccessTime(int accessTime) {
        if (this.accessTime == null || this.accessTime.getOriginalValue() == null) {
            this.accessTime = ModifiableVariableFactory.safelySetValue(this.accessTime, accessTime);
        }
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

    public void setSoftlyModifyTime(int modifyTime) {
        if (this.modifyTime == null || this.modifyTime.getOriginalValue() == null) {
            this.modifyTime = ModifiableVariableFactory.safelySetValue(this.modifyTime, modifyTime);
        }
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

    public void setSoftlyExtendedCount(int extendedCount, Config config) {
        if (config.getAlwaysPrepareSftpLengthFields()
                || this.extendedCount == null
                || this.extendedCount.getOriginalValue() == null) {
            this.extendedCount =
                    ModifiableVariableFactory.safelySetValue(this.extendedCount, extendedCount);
        }
    }

    public void clearExtendedAttributes() {
        extendedCount = null;
        extendedAttributes = new ArrayList<>();
    }

    public List<SftpFileExtendedAttribute> getExtendedAttributes() {
        return extendedAttributes;
    }

    public void setExtendedAttributes(ArrayList<SftpFileExtendedAttribute> extendedAttributes) {
        setExtendedAttributes(extendedAttributes, false);
    }

    public void setExtendedAttributes(
            ArrayList<SftpFileExtendedAttribute> extendedAttributes, boolean adjustLengthField) {
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

    public void setSoftlyType(byte type) {
        if (this.type == null || this.type.getOriginalValue() == null) {
            this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
        }
    }

    public void setType(SftpFileType type) {
        setType(type.getType());
    }

    public void setSoftlyType(SftpFileType type) {
        setSoftlyType(type.getType());
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
        this.owner = ModifiableVariableFactory.safelySetValue(this.owner, owner);
        if (adjustLengthField) {
            setOwnerLength(this.owner.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyOwner(String owner, boolean adjustLengthField, Config config) {
        if (this.owner == null || this.owner.getOriginalValue() == null) {
            this.owner = ModifiableVariableFactory.safelySetValue(this.owner, owner);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || ownerLength == null
                    || ownerLength.getOriginalValue() == null) {
                setOwnerLength(this.owner.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
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
        this.group = ModifiableVariableFactory.safelySetValue(this.group, group);
        if (adjustLengthField) {
            setGroupLength(this.group.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyGroup(String group, boolean adjustLengthField, Config config) {
        if (this.group == null || this.group.getOriginalValue() == null) {
            this.group = ModifiableVariableFactory.safelySetValue(this.group, group);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || groupLength == null
                    || groupLength.getOriginalValue() == null) {
                setGroupLength(this.group.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
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

    public void setSoftlyCreateTime(int createTime) {
        if (this.createTime == null || this.createTime.getOriginalValue() == null) {
            this.createTime = ModifiableVariableFactory.safelySetValue(this.createTime, createTime);
        }
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

    public void setSoftlyAclLength(int aclLength, Config config) {
        if (config.getAlwaysPrepareSftpLengthFields()
                || this.aclLength == null
                || this.aclLength.getOriginalValue() == null) {
            this.aclLength = ModifiableVariableFactory.safelySetValue(this.aclLength, aclLength);
        }
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

    public void setSoftlyAclEntriesCount(int aclEntriesCount, Config config) {
        if (config.getAlwaysPrepareSftpLengthFields()
                || this.aclEntriesCount == null
                || this.aclEntriesCount.getOriginalValue() == null) {
            this.aclEntriesCount =
                    ModifiableVariableFactory.safelySetValue(this.aclEntriesCount, aclEntriesCount);
        }
    }

    public List<SftpAclEntry> getAclEntries() {
        return aclEntries;
    }

    public void setAclEntries(ArrayList<SftpAclEntry> aclEntries) {
        setAclEntries(aclEntries, false);
    }

    public void setAclEntries(ArrayList<SftpAclEntry> aclEntries, boolean adjustLengthField) {
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
        if (extendedAttributes != null) {
            holders.addAll(extendedAttributes);
        }
        if (aclEntries != null) {
            holders.addAll(aclEntries);
        }
        return holders;
    }
}
