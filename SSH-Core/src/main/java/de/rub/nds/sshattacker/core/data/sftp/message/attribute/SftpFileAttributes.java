/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.attribute;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.data.sftp.handler.attribute.SftpFileAttributesHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;

public class SftpFileAttributes extends ModifiableVariableHolder {

    private ModifiableInteger flags;
    private ModifiableLong size;
    private ModifiableInteger uId;
    private ModifiableInteger gId;
    private ModifiableInteger permissions;
    private ModifiableInteger aTime;
    private ModifiableInteger mTime;
    private ModifiableInteger extendedCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements({
        @XmlElement(type = SftpFileExtendedAttribute.class, name = "SftpFileExtendedAttribute")
    })
    private List<SftpFileExtendedAttribute> extendedAttributes = new ArrayList<>();

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

    public ModifiableInteger getUId() {
        return uId;
    }

    public void setUId(ModifiableInteger uId) {
        this.uId = uId;
    }

    public void setUId(int uId) {
        this.uId = ModifiableVariableFactory.safelySetValue(this.uId, uId);
    }

    public ModifiableInteger getGId() {
        return gId;
    }

    public void setGId(ModifiableInteger gId) {
        this.gId = gId;
    }

    public void setGId(int gId) {
        this.gId = ModifiableVariableFactory.safelySetValue(this.gId, gId);
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

    public ModifiableInteger getATime() {
        return aTime;
    }

    public void setATime(ModifiableInteger aTime) {
        this.aTime = aTime;
    }

    public void setATime(int aTime) {
        this.aTime = ModifiableVariableFactory.safelySetValue(this.aTime, aTime);
    }

    public ModifiableInteger getMTime() {
        return mTime;
    }

    public void setMTime(ModifiableInteger mTime) {
        this.mTime = mTime;
    }

    public void setMTime(int mTime) {
        this.mTime = ModifiableVariableFactory.safelySetValue(this.mTime, mTime);
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

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        holders.addAll(extendedAttributes);
        return holders;
    }
}
