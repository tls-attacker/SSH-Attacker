/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.SftpFileOpenFlag;
import de.rub.nds.sshattacker.core.data.sftp.handler.SftpRequestOpenMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SftpRequestOpenMessage extends SftpRequestMessage<SftpRequestOpenMessage> {

    private ModifiableInteger filenameLength;
    private ModifiableString filename;
    private ModifiableInteger pFlags;
    private SftpFileAttributes attributes;

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

    public ModifiableInteger getPFlags() {
        return pFlags;
    }

    public void setPFlags(ModifiableInteger pFlags) {
        this.pFlags = pFlags;
    }

    public void setPFlags(int pFlags) {
        this.pFlags = ModifiableVariableFactory.safelySetValue(this.pFlags, pFlags);
    }

    public void setPFlags(SftpFileOpenFlag... fileOpenFlags) {
        setPFlags(SftpFileOpenFlag.flagsToInt(fileOpenFlags));
    }

    public SftpFileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpFileAttributes attributes) {
        this.attributes = attributes;
    }

    @Override
    public SftpRequestOpenMessageHandler getHandler(SshContext context) {
        return new SftpRequestOpenMessageHandler(context, this);
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
