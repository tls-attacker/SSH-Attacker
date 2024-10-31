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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.data.sftp.handler.SftpResponseNameEntryHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SftpResponseNameEntry extends ModifiableVariableHolder {

    private ModifiableInteger filenameLength;
    private ModifiableString filename;
    private ModifiableInteger longNameLength;
    private ModifiableString longName;

    @HoldsModifiableVariable private SftpFileAttributes attributes;

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
        if (adjustLengthField) {
            setFilenameLength(filename.getBytes(StandardCharsets.UTF_8).length);
        }
        this.filename = ModifiableVariableFactory.safelySetValue(this.filename, filename);
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
        if (adjustLengthField) {
            setLongNameLength(longName.getBytes(StandardCharsets.UTF_8).length);
        }
        this.longName = ModifiableVariableFactory.safelySetValue(this.longName, longName);
    }

    public SftpFileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpFileAttributes attributes) {
        this.attributes = attributes;
    }

    public SftpResponseNameEntryHandler getHandler(SshContext context) {
        return new SftpResponseNameEntryHandler(context, this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        holders.addAll(attributes.getAllModifiableVariableHolders());
        return holders;
    }
}
