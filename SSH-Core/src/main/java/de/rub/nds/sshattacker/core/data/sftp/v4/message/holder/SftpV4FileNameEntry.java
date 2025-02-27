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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.data.sftp.v4.handler.holder.SftpV4FileNameEntryHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** LongName was removed in SFTP V4 */
public class SftpV4FileNameEntry extends ModifiableVariableHolder {

    private ModifiableInteger filenameLength;
    private ModifiableString filename;

    @HoldsModifiableVariable private SftpV4FileAttributes attributes = new SftpV4FileAttributes();

    public SftpV4FileNameEntry() {
        super();
    }

    public SftpV4FileNameEntry(SftpV4FileNameEntry other) {
        super(other);
        filenameLength = other.filenameLength != null ? other.filenameLength.createCopy() : null;
        filename = other.filename != null ? other.filename.createCopy() : null;
        attributes = other.attributes != null ? other.attributes.createCopy() : null;
    }

    @Override
    public SftpV4FileNameEntry createCopy() {
        return new SftpV4FileNameEntry(this);
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

    public SftpV4FileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpV4FileAttributes attributes) {
        this.attributes = attributes;
    }

    public static final SftpV4FileNameEntryHandler HANDLER = new SftpV4FileNameEntryHandler();

    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    public void prepare(Chooser chooser) {
        SftpV4FileNameEntryHandler.PREPARATOR.prepare(this, chooser);
    }

    public byte[] serialize() {
        return SftpV4FileNameEntryHandler.SERIALIZER.serialize(this);
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
