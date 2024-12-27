/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthInfoResponseMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;

public class UserAuthInfoResponseMessage extends SshMessage<UserAuthInfoResponseMessage> {

    private ModifiableInteger responseEntriesCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            @XmlElement(
                    type = AuthenticationResponseEntry.class,
                    name = "AuthenticationResponseEntry"))
    private ArrayList<AuthenticationResponseEntry> responseEntries = new ArrayList<>();

    public UserAuthInfoResponseMessage() {
        super();
    }

    public UserAuthInfoResponseMessage(UserAuthInfoResponseMessage other) {
        super(other);
        responseEntriesCount =
                other.responseEntriesCount != null ? other.responseEntriesCount.createCopy() : null;
        if (other.responseEntries != null) {
            responseEntries = new ArrayList<>(other.responseEntries.size());
            for (AuthenticationResponseEntry item : other.responseEntries) {
                responseEntries.add(item != null ? item.createCopy() : null);
            }
        }
    }

    @Override
    public UserAuthInfoResponseMessage createCopy() {
        return new UserAuthInfoResponseMessage(this);
    }

    public ModifiableInteger getResponseEntriesCount() {
        return responseEntriesCount;
    }

    public void setResponseEntriesCount(ModifiableInteger responseEntriesCount) {
        this.responseEntriesCount = responseEntriesCount;
    }

    public void setResponseEntriesCount(int responseEntriesCount) {
        this.responseEntriesCount =
                ModifiableVariableFactory.safelySetValue(
                        this.responseEntriesCount, responseEntriesCount);
    }

    public void setSoftlyResponseEntriesCount(int responseEntriesCount, Config config) {
        if (config.getAlwaysPrepareLengthFields()
                || this.responseEntriesCount == null
                || this.responseEntriesCount.getOriginalValue() == null) {
            this.responseEntriesCount =
                    ModifiableVariableFactory.safelySetValue(
                            this.responseEntriesCount, responseEntriesCount);
        }
    }

    public ArrayList<AuthenticationResponseEntry> getResponseEntries() {
        return responseEntries;
    }

    public void setResponseEntries(ArrayList<AuthenticationResponseEntry> responseEntries) {
        setResponseEntries(responseEntries, false);
    }

    public void setResponseEntries(
            ArrayList<AuthenticationResponseEntry> responseEntries, boolean adjustLengthField) {
        if (adjustLengthField) {
            setResponseEntriesCount(responseEntries.size());
        }
        this.responseEntries = responseEntries;
    }

    public void setSoftlyResponseEntries(
            ArrayList<AuthenticationResponseEntry> responseEntries,
            boolean adjustLengthField,
            Config config) {
        if (config.getAlwaysPrepareAuthentication()
                || this.responseEntries == null
                || this.responseEntries.isEmpty()) {
            this.responseEntries = responseEntries;
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || responseEntriesCount == null
                    || responseEntriesCount.getOriginalValue() == null) {
                setResponseEntriesCount(this.responseEntries.size());
            }
        }
    }

    public void addResponseEntry(AuthenticationResponseEntry responseEntry) {
        addResponseEntry(responseEntry, false);
    }

    public void addResponseEntry(
            AuthenticationResponseEntry responseEntry, boolean adjustLengthField) {
        responseEntries.add(responseEntry);
        if (adjustLengthField) {
            setResponseEntriesCount(responseEntries.size());
        }
    }

    @Override
    public UserAuthInfoResponseMessageHandler getHandler(SshContext context) {
        return new UserAuthInfoResponseMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UserAuthInfoResponseMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return UserAuthInfoResponseMessageHandler.SERIALIZER.serialize(this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (responseEntries != null) {
            holders.addAll(responseEntries);
        }
        return holders;
    }
}
