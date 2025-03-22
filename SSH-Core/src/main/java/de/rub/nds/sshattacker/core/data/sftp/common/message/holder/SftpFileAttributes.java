/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.holder;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.data.sftp.common.handler.holder.SftpFileAttributesHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;

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

    public static final SftpFileAttributesHandler HANDLER = new SftpFileAttributesHandler();

    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    public void prepare(Chooser chooser) {
        SftpFileAttributesHandler.PREPARATOR.prepare(this, chooser);
    }

    public byte[] serialize() {
        return SftpFileAttributesHandler.SERIALIZER.serialize(this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (extendedAttributes != null) {
            holders.addAll(extendedAttributes);
        }
        return holders;
    }
}
