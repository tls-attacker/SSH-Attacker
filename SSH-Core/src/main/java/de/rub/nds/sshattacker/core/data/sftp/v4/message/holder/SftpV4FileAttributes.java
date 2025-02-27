/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.message.holder;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.constants.SftpFileType;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.data.sftp.v4.handler.holder.SftpV4FileAttributesHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * In SFTP V4: userId and groupId was replaced by owner and group; accessTime and modifyTime was
 * replaced by long values and integers for nanoseconds; createTime was added; Also ACL was added
 */
public class SftpV4FileAttributes extends ModifiableVariableHolder {

    private ModifiableInteger flags;
    private ModifiableLong size;
    private ModifiableInteger permissions;
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

    // As of version 4 there are fields for nanoseconds, and the actual time fields are now int64
    // This change is done in the second draft of version 4:
    // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-04#page-10
    private ModifiableLong accessTimeLong;
    private ModifiableInteger accessTimeNanoseconds;
    private ModifiableLong createTimeLong;
    private ModifiableInteger createTimeNanoseconds;
    private ModifiableLong modifyTimeLong;
    private ModifiableInteger modifyTimeNanoseconds;

    private ModifiableInteger aclLength;
    private ModifiableInteger aclEntriesCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = SftpAclEntry.class, name = "SftpAclEntry"))
    private ArrayList<SftpAclEntry> aclEntries = new ArrayList<>();

    // TODO: SFTPv5 defines attrib-bits field

    public SftpV4FileAttributes() {
        super();
    }

    public SftpV4FileAttributes(SftpV4FileAttributes other) {
        super(other);
        flags = other.flags != null ? other.flags.createCopy() : null;
        size = other.size != null ? other.size.createCopy() : null;
        permissions = other.permissions != null ? other.permissions.createCopy() : null;
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
        accessTimeLong = other.accessTimeLong != null ? other.accessTimeLong.createCopy() : null;
        accessTimeNanoseconds =
                other.accessTimeNanoseconds != null
                        ? other.accessTimeNanoseconds.createCopy()
                        : null;
        createTimeLong = other.createTimeLong != null ? other.createTimeLong.createCopy() : null;
        createTimeNanoseconds =
                other.createTimeNanoseconds != null
                        ? other.createTimeNanoseconds.createCopy()
                        : null;
        modifyTimeLong = other.modifyTimeLong != null ? other.modifyTimeLong.createCopy() : null;
        modifyTimeNanoseconds =
                other.modifyTimeNanoseconds != null
                        ? other.modifyTimeNanoseconds.createCopy()
                        : null;
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
    public SftpV4FileAttributes createCopy() {
        return new SftpV4FileAttributes(this);
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
        this.owner = ModifiableVariableFactory.safelySetValue(this.owner, owner);
        if (adjustLengthField) {
            setOwnerLength(this.owner.getValue().getBytes(StandardCharsets.UTF_8).length);
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

    public void clearGroup() {
        groupLength = null;
        group = null;
    }

    public ModifiableLong getAccessTimeLong() {
        return accessTimeLong;
    }

    public void setAccessTimeLong(ModifiableLong accessTimeLong) {
        this.accessTimeLong = accessTimeLong;
    }

    public void setAccessTimeLong(long accessTimeLong) {
        this.accessTimeLong =
                ModifiableVariableFactory.safelySetValue(this.accessTimeLong, accessTimeLong);
    }

    public void clearAccessTimeLong() {
        accessTimeLong = null;
    }

    public ModifiableInteger getAccessTimeNanoseconds() {
        return accessTimeNanoseconds;
    }

    public void setAccessTimeNanoseconds(ModifiableInteger accessTimeNanoseconds) {
        this.accessTimeNanoseconds = accessTimeNanoseconds;
    }

    public void setAccessTimeNanoseconds(int accessTimeNanoseconds) {
        this.accessTimeNanoseconds =
                ModifiableVariableFactory.safelySetValue(
                        this.accessTimeNanoseconds, accessTimeNanoseconds);
    }

    public void clearAccessTimeNanoseconds() {
        accessTimeNanoseconds = null;
    }

    public ModifiableLong getCreateTimeLong() {
        return createTimeLong;
    }

    public void setCreateTimeLong(ModifiableLong createTimeLong) {
        this.createTimeLong = createTimeLong;
    }

    public void setCreateTimeLong(long createTimeLong) {
        this.createTimeLong =
                ModifiableVariableFactory.safelySetValue(this.createTimeLong, createTimeLong);
    }

    public void clearCreateTimeLong() {
        createTimeLong = null;
    }

    public ModifiableInteger getCreateTimeNanoseconds() {
        return createTimeNanoseconds;
    }

    public void setCreateTimeNanoseconds(ModifiableInteger createTimeNanoseconds) {
        this.createTimeNanoseconds = createTimeNanoseconds;
    }

    public void setCreateTimeNanoseconds(int createTimeNanoseconds) {
        this.createTimeNanoseconds =
                ModifiableVariableFactory.safelySetValue(
                        this.createTimeNanoseconds, createTimeNanoseconds);
    }

    public void clearCreateTimeNanoseconds() {
        createTimeNanoseconds = null;
    }

    public ModifiableLong getModifyTimeLong() {
        return modifyTimeLong;
    }

    public void setModifyTimeLong(ModifiableLong modifyTimeLong) {
        this.modifyTimeLong = modifyTimeLong;
    }

    public void setModifyTimeLong(long modifyTimeLong) {
        this.modifyTimeLong =
                ModifiableVariableFactory.safelySetValue(this.modifyTimeLong, modifyTimeLong);
    }

    public void clearModifyTimeLong() {
        modifyTimeLong = null;
    }

    public void clearAllLongTimes() {
        createTimeLong = null;
        modifyTimeLong = null;
        accessTimeLong = null;
    }

    public ModifiableInteger getModifyTimeNanoseconds() {
        return modifyTimeNanoseconds;
    }

    public void setModifyTimeNanoseconds(ModifiableInteger modifyTimeNanoseconds) {
        this.modifyTimeNanoseconds = modifyTimeNanoseconds;
    }

    public void setModifyTimeNanoseconds(int modifyTimeNanoseconds) {
        this.modifyTimeNanoseconds =
                ModifiableVariableFactory.safelySetValue(
                        this.modifyTimeNanoseconds, modifyTimeNanoseconds);
    }

    public void clearModifyTimeNanoseconds() {
        modifyTimeNanoseconds = null;
    }

    public void clearAllNanoseconds() {
        createTimeNanoseconds = null;
        modifyTimeNanoseconds = null;
        accessTimeNanoseconds = null;
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

    public static final SftpV4FileAttributesHandler HANDLER = new SftpV4FileAttributesHandler();

    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    public void prepare(Chooser chooser) {
        SftpV4FileAttributesHandler.PREPARATOR.prepare(this, chooser);
    }

    public byte[] serialize() {
        return SftpV4FileAttributesHandler.SERIALIZER.serialize(this);
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
