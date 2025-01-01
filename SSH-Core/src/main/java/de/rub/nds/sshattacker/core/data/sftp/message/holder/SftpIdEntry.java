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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

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

    public static final SftpIdEntryHandler HANDLER = new SftpIdEntryHandler();

    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    public void prepare(Chooser chooser) {
        SftpIdEntryHandler.PREPARATOR.prepare(this, chooser);
    }

    public byte[] serialize() {
        return SftpIdEntryHandler.SERIALIZER.serialize(this);
    }
}
