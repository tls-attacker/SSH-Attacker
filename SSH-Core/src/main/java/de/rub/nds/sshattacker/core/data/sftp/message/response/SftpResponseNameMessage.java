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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;

public class SftpResponseNameMessage extends SftpResponseMessage<SftpResponseNameMessage> {

    private ModifiableInteger nameEntriesCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = SftpFileNameEntry.class, name = "SftpResponseNameEntry"))
    private ArrayList<SftpFileNameEntry> nameEntries = new ArrayList<>();

    public SftpResponseNameMessage() {
        super();
    }

    public SftpResponseNameMessage(SftpResponseNameMessage other) {
        super(other);
        nameEntriesCount =
                other.nameEntriesCount != null ? other.nameEntriesCount.createCopy() : null;
        if (other.nameEntries != null) {
            nameEntries = new ArrayList<>(other.nameEntries.size());
            for (SftpFileNameEntry item : other.nameEntries) {
                nameEntries.add(item != null ? item.createCopy() : null);
            }
        }
    }

    @Override
    public SftpResponseNameMessage createCopy() {
        return new SftpResponseNameMessage(this);
    }

    public ModifiableInteger getNameEntriesCount() {
        return nameEntriesCount;
    }

    public void setNameEntriesCount(ModifiableInteger nameEntriesCount) {
        this.nameEntriesCount = nameEntriesCount;
    }

    public void setNameEntriesCount(int nameEntriesCount) {
        this.nameEntriesCount =
                ModifiableVariableFactory.safelySetValue(this.nameEntriesCount, nameEntriesCount);
    }

    public List<SftpFileNameEntry> getNameEntries() {
        return nameEntries;
    }

    public void setNameEntries(ArrayList<SftpFileNameEntry> nameEntries) {
        setNameEntries(nameEntries, false);
    }

    public void setNameEntries(
            ArrayList<SftpFileNameEntry> nameEntries, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNameEntriesCount(nameEntries.size());
        }
        this.nameEntries = nameEntries;
    }

    public void addNameEntry(SftpFileNameEntry nameEntry) {
        addNameEntry(nameEntry, false);
    }

    public void addNameEntry(SftpFileNameEntry nameEntry, boolean adjustLengthField) {
        nameEntries.add(nameEntry);
        if (adjustLengthField) {
            setNameEntriesCount(nameEntries.size());
        }
    }

    public static final SftpResponseNameMessageHandler HANDLER =
            new SftpResponseNameMessageHandler();

    @Override
    public SftpResponseNameMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpResponseNameMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpResponseNameMessageHandler.SERIALIZER.serialize(this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (nameEntries != null) {
            for (SftpFileNameEntry nameEntry : nameEntries) {
                holders.addAll(nameEntry.getAllModifiableVariableHolders());
            }
        }
        return holders;
    }
}
