/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.holder;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.data.sftp.common.handler.holder.SftpNameEntryHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class SftpNameEntry extends ModifiableVariableHolder {

    private ModifiableInteger nameLength;
    private ModifiableString name;

    public SftpNameEntry(SftpNameEntry other) {
        super(other);
        nameLength = other.nameLength != null ? other.nameLength.createCopy() : null;
        name = other.name != null ? other.name.createCopy() : null;
    }

    @Override
    public SftpNameEntry createCopy() {
        return new SftpNameEntry(this);
    }

    public SftpNameEntry() {
        super();
    }

    public SftpNameEntry(ModifiableString name) {
        super();
        setName(name, true);
    }

    public ModifiableInteger getNameLength() {
        return nameLength;
    }

    public void setNameLength(ModifiableInteger nameLength) {
        this.nameLength = nameLength;
    }

    public void setNameLength(int nameLength) {
        this.nameLength = ModifiableVariableFactory.safelySetValue(this.nameLength, nameLength);
    }

    public ModifiableString getName() {
        return name;
    }

    public void setName(ModifiableString name) {
        setName(name, false);
    }

    public void setName(String name) {
        setName(name, false);
    }

    public void setName(ModifiableString name, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNameLength(name.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.name = name;
    }

    public void setName(String name, boolean adjustLengthField) {
        this.name = ModifiableVariableFactory.safelySetValue(this.name, name);
        if (adjustLengthField) {
            setNameLength(this.name.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public static final SftpNameEntryHandler HANDLER = new SftpNameEntryHandler();

    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    public void prepare(Chooser chooser) {
        SftpNameEntryHandler.PREPARATOR.prepare(this, chooser);
    }

    public byte[] serialize() {
        return SftpNameEntryHandler.SERIALIZER.serialize(this);
    }
}
