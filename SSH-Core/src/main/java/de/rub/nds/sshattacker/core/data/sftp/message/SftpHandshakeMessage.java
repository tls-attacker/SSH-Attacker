/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessage;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.*;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;

public abstract class SftpHandshakeMessage<T extends SftpHandshakeMessage<T>>
        extends SftpMessage<T> {

    private ModifiableInteger version;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements({
        @XmlElement(type = SftpExtensionCheckFile.class, name = "SftpExtensionCheckFile"),
        @XmlElement(type = SftpExtensionCopyData.class, name = "SftpExtensionCopyData"),
        @XmlElement(type = SftpExtensionCopyFile.class, name = "SftpExtensionCopyFile"),
        @XmlElement(type = SftpExtensionExpandPath.class, name = "SftpExtensionExpandPath"),
        @XmlElement(type = SftpExtensionFileStatVfs.class, name = "SftpExtensionFileStatVfs"),
        @XmlElement(type = SftpExtensionFileSync.class, name = "SftpExtensionFileSync"),
        @XmlElement(type = SftpExtensionGetTempFolder.class, name = "SftpExtensionGetTempFolder"),
        @XmlElement(type = SftpExtensionHardlink.class, name = "SftpExtensionHardlink"),
        @XmlElement(type = SftpExtensionHomeDirectory.class, name = "SftpExtensionHomeDirectory"),
        @XmlElement(type = SftpExtensionLimits.class, name = "SftpExtensionLimits"),
        @XmlElement(type = SftpExtensionLinkSetStat.class, name = "SftpExtensionLinkSetStat"),
        @XmlElement(type = SftpExtensionMakeTempFolder.class, name = "SftpExtensionMakeTempFolder"),
        @XmlElement(type = SftpExtensionNewline.class, name = "SftpExtensionNewline"),
        @XmlElement(type = SftpExtensionPosixRename.class, name = "SftpExtensionPosixRename"),
        @XmlElement(type = SftpExtensionSpaceAvailable.class, name = "SftpExtensionSpaceAvailable"),
        @XmlElement(type = SftpExtensionStatVfs.class, name = "SftpExtensionStatVfs"),
        @XmlElement(type = SftpExtensionTextSeek.class, name = "SftpExtensionTextSeek"),
        @XmlElement(type = SftpExtensionUnknown.class, name = "SftpExtensionUnknown"),
        @XmlElement(
                type = SftpExtensionUsersGroupsById.class,
                name = "SftpExtensionUsersGroupsById"),
        @XmlElement(type = SftpExtensionVendorId.class, name = "SftpExtensionVendorId"),
        @XmlElement(type = SftpExtensionWithVersion.class, name = "SftpExtensionWithVersion")
    })
    private List<SftpAbstractExtension<?>> extensions = new ArrayList<>();

    public ModifiableInteger getVersion() {
        return version;
    }

    public void setVersion(ModifiableInteger version) {
        this.version = version;
    }

    public void setVersion(Integer version) {
        this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
    }

    public List<SftpAbstractExtension<?>> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<SftpAbstractExtension<?>> extensions) {
        this.extensions = extensions;
    }

    public void addExtension(SftpAbstractExtension<?> extension) {
        extensions.add(extension);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        holders.addAll(extensions);
        return holders;
    }
}
