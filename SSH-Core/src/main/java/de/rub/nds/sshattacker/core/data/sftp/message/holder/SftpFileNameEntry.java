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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.holder.SftpFileNameEntryHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.nio.charset.StandardCharsets;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
public class SftpFileNameEntry extends ModifiableVariableHolder {

    private ModifiableInteger filenameLength;
    private ModifiableString filename;
    private ModifiableInteger longNameLength;
    private ModifiableString longName;

    @HoldsModifiableVariable private SftpFileAttributes attributes = new SftpFileAttributes();

    public SftpFileNameEntry() {
        super();
    }

    public SftpFileNameEntry(SftpFileNameEntry other) {
        super(other);
        filenameLength = other.filenameLength != null ? other.filenameLength.createCopy() : null;
        filename = other.filename != null ? other.filename.createCopy() : null;
        longNameLength = other.longNameLength != null ? other.longNameLength.createCopy() : null;
        longName = other.longName != null ? other.longName.createCopy() : null;
        attributes = other.attributes != null ? other.attributes.createCopy() : null;
    }

    @Override
    public SftpFileNameEntry createCopy() {
        return new SftpFileNameEntry(this);
    }

    public ModifiableInteger getFilenameLength() {
        return filenameLength;
    }

    public void setFilenameLength(ModifiableInteger filenameLength) {
        this.filenameLength = filenameLength;
    }

    public void setFilenameLength(int filenameLength) {
        this.filenameLength =
                ModifiableVariableFactory.safelySetValue(this.filenameLength, filenameLength);
    }

    public ModifiableString getFilename() {
        return filename;
    }

    public void setFilename(ModifiableString filename) {
        setFilename(filename, false);
    }

    public void setFilename(String filename) {
        setFilename(filename, false);
    }

    public void setFilename(ModifiableString filename, boolean adjustLengthField) {
        if (adjustLengthField) {
            setFilenameLength(filename.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.filename = filename;
    }

    public void setFilename(String filename, boolean adjustLengthField) {
        this.filename = ModifiableVariableFactory.safelySetValue(this.filename, filename);
        if (adjustLengthField) {
            setFilenameLength(this.filename.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyFilename(String filename, boolean adjustLengthField, Config config) {
        if (this.filename == null || this.filename.getOriginalValue() == null) {
            this.filename = ModifiableVariableFactory.safelySetValue(this.filename, filename);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || filenameLength == null
                    || filenameLength.getOriginalValue() == null) {
                setFilenameLength(this.filename.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    public ModifiableInteger getLongNameLength() {
        return longNameLength;
    }

    public void setLongNameLength(ModifiableInteger longNameLength) {
        this.longNameLength = longNameLength;
    }

    public void setLongNameLength(int longNameLength) {
        this.longNameLength =
                ModifiableVariableFactory.safelySetValue(this.longNameLength, longNameLength);
    }

    public ModifiableString getLongName() {
        return longName;
    }

    public void setLongName(ModifiableString longName) {
        setLongName(longName, false);
    }

    public void setLongName(String longName) {
        setLongName(longName, false);
    }

    public void setLongName(ModifiableString longName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setLongNameLength(longName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.longName = longName;
    }

    public void setLongName(String longName, boolean adjustLengthField) {
        this.longName = ModifiableVariableFactory.safelySetValue(this.longName, longName);
        if (adjustLengthField) {
            setLongNameLength(this.longName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyLongName(String longName, boolean adjustLengthField, Config config) {
        if (this.longName == null || this.longName.getOriginalValue() == null) {
            this.longName = ModifiableVariableFactory.safelySetValue(this.longName, longName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || longNameLength == null
                    || longNameLength.getOriginalValue() == null) {
                setLongNameLength(this.longName.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    public void clearLongName() {
        longName = null;
        longNameLength = null;
    }

    public SftpFileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpFileAttributes attributes) {
        this.attributes = attributes;
    }

    public SftpFileNameEntryHandler getHandler(SshContext context) {
        return new SftpFileNameEntryHandler(context, this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (attributes != null) {
            holders.addAll(attributes.getAllModifiableVariableHolders());
        }
        return holders;
    }
}
