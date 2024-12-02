/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.holder;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.data.sftp.handler.holder.SftpIdEntryHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.FIELD)
public class SftpIdEntry extends ModifiableVariableHolder {

    private ModifiableInteger id;

    public SftpIdEntry(SftpIdEntry other) {
        super(other);
        id = other.id != null ? other.id.createCopy() : null;
    }

    @Override
    public SftpIdEntry createCopy() {
        return new SftpIdEntry(this);
    }

    public SftpIdEntry() {
        super();
    }

    public SftpIdEntry(ModifiableInteger id) {
        super();
        this.id = id;
    }

    public ModifiableInteger getId() {
        return id;
    }

    public void setId(ModifiableInteger id) {
        this.id = id;
    }

    public void setId(int id) {
        this.id = ModifiableVariableFactory.safelySetValue(this.id, id);
    }

    public void setSoftlyId(int id) {
        if (this.id == null || this.id.getOriginalValue() == null) {
            this.id = ModifiableVariableFactory.safelySetValue(this.id, id);
        }
    }

    public SftpIdEntryHandler getHandler(SshContext context) {
        return new SftpIdEntryHandler(context, this);
    }
}
