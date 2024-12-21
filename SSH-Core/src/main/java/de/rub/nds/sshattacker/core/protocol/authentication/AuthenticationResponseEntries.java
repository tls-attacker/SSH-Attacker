/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication;

import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import jakarta.xml.bind.annotation.*;
import java.io.Serializable;
import java.util.*;

/** Helper class for pre-configured AuthenticationResponseEntries */
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthenticationResponseEntries implements Serializable {

    @XmlElementWrapper
    @XmlElement(name = "responseEntry")
    private ArrayList<AuthenticationResponseEntry> responseEntries;

    public AuthenticationResponseEntries() {
        super();
    }

    public AuthenticationResponseEntries(ArrayList<AuthenticationResponseEntry> responseEntries) {
        super();
        this.responseEntries = responseEntries;
    }

    public AuthenticationResponseEntries(AuthenticationResponseEntries other) {
        super();
        if (other.responseEntries != null) {
            responseEntries = new ArrayList<>(other.responseEntries.size());
            for (AuthenticationResponseEntry item : other.responseEntries) {
                responseEntries.add(item != null ? item.createCopy() : null);
            }
        } else {
            responseEntries = null;
        }
    }

    public AuthenticationResponseEntries createCopy() {
        return new AuthenticationResponseEntries(this);
    }

    public ArrayList<AuthenticationResponseEntry> getResponseEntries() {
        return responseEntries;
    }

    public void setResponseEntries(ArrayList<AuthenticationResponseEntry> responseEntries) {
        this.responseEntries = responseEntries;
    }
}
