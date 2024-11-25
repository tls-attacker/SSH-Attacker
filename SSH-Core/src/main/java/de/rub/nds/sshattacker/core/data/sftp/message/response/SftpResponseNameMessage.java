/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.response;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.data.sftp.handler.response.SftpResponseNameMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;

public class SftpResponseNameMessage extends SftpResponseMessage<SftpResponseNameMessage> {

    private ModifiableInteger countNameEntries;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements({@XmlElement(type = SftpFileNameEntry.class, name = "SftpResponseNameEntry")})
    private List<SftpFileNameEntry> nameEntries = new ArrayList<>();

    public ModifiableInteger getCountNameEntries() {
        return countNameEntries;
    }

    public void setCountNameEntries(ModifiableInteger countNameEntries) {
        this.countNameEntries = countNameEntries;
    }

    public void setCountNameEntries(int countNameEntries) {
        this.countNameEntries =
                ModifiableVariableFactory.safelySetValue(this.countNameEntries, countNameEntries);
    }

    public List<SftpFileNameEntry> getNameEntries() {
        return nameEntries;
    }

    public void setNameEntries(List<SftpFileNameEntry> nameEntries) {
        setNameEntries(nameEntries, false);
    }

    public void setNameEntries(List<SftpFileNameEntry> nameEntries, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCountNameEntries(nameEntries.size());
        }
        this.nameEntries = nameEntries;
    }

    public void addNameEntry(SftpFileNameEntry nameEntry) {
        addNameEntry(nameEntry, false);
    }

    public void addNameEntry(SftpFileNameEntry nameEntry, boolean adjustLengthField) {
        nameEntries.add(nameEntry);
        if (adjustLengthField) {
            setCountNameEntries(nameEntries.size());
        }
    }

    @Override
    public SftpResponseNameMessageHandler getHandler(SshContext context) {
        return new SftpResponseNameMessageHandler(context, this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        for (SftpFileNameEntry nameEntry : nameEntries) {
            holders.addAll(nameEntry.getAllModifiableVariableHolders());
        }
        return holders;
    }
}
