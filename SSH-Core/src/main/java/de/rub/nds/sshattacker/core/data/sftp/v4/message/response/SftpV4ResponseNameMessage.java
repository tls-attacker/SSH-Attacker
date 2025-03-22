/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.message.response;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.data.sftp.common.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.handler.response.SftpV4ResponseNameMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;

public class SftpV4ResponseNameMessage extends SftpResponseMessage<SftpV4ResponseNameMessage> {

    private ModifiableInteger nameEntriesCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = SftpV4FileNameEntry.class, name = "SftpResponseNameEntry"))
    private ArrayList<SftpV4FileNameEntry> nameEntries = new ArrayList<>();

    public SftpV4ResponseNameMessage() {
        super();
    }

    public SftpV4ResponseNameMessage(SftpV4ResponseNameMessage other) {
        super(other);
        nameEntriesCount =
                other.nameEntriesCount != null ? other.nameEntriesCount.createCopy() : null;
        if (other.nameEntries != null) {
            nameEntries = new ArrayList<>(other.nameEntries.size());
            for (SftpV4FileNameEntry item : other.nameEntries) {
                nameEntries.add(item != null ? item.createCopy() : null);
            }
        }
    }

    @Override
    public SftpV4ResponseNameMessage createCopy() {
        return new SftpV4ResponseNameMessage(this);
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

    public List<SftpV4FileNameEntry> getNameEntries() {
        return nameEntries;
    }

    public void setNameEntries(ArrayList<SftpV4FileNameEntry> nameEntries) {
        setNameEntries(nameEntries, false);
    }

    public void setNameEntries(
            ArrayList<SftpV4FileNameEntry> nameEntries, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNameEntriesCount(nameEntries.size());
        }
        this.nameEntries = nameEntries;
    }

    public void addNameEntry(SftpV4FileNameEntry nameEntry) {
        addNameEntry(nameEntry, false);
    }

    public void addNameEntry(SftpV4FileNameEntry nameEntry, boolean adjustLengthField) {
        nameEntries.add(nameEntry);
        if (adjustLengthField) {
            setNameEntriesCount(nameEntries.size());
        }
    }

    public static final SftpV4ResponseNameMessageHandler HANDLER =
            new SftpV4ResponseNameMessageHandler();

    @Override
    public SftpV4ResponseNameMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpV4ResponseNameMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpV4ResponseNameMessageHandler.SERIALIZER.serialize(this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (nameEntries != null) {
            for (SftpV4FileNameEntry nameEntry : nameEntries) {
                holders.addAll(nameEntry.getAllModifiableVariableHolders());
            }
        }
        return holders;
    }
}
