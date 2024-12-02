/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication;

import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import jakarta.xml.bind.annotation.*;
import java.io.Serializable;
import java.util.*;

/** Helper class for pre-configured AuthenticationPromptEntries */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthenticationPromptEntries implements Serializable {

    @XmlElementWrapper
    @XmlElement(name = "promptEntry")
    private ArrayList<AuthenticationPromptEntry> promptEntries;

    public AuthenticationPromptEntries() {
        super();
    }

    public AuthenticationPromptEntries(ArrayList<AuthenticationPromptEntry> promptEntries) {
        super();
        this.promptEntries = promptEntries;
    }

    public AuthenticationPromptEntries(AuthenticationPromptEntries other) {
        super();
        if (other.promptEntries != null) {
            promptEntries = new ArrayList<>();
            for (AuthenticationPromptEntry item : other.promptEntries) {
                promptEntries.add(item != null ? item.createCopy() : null);
            }
        } else {
            promptEntries = null;
        }
    }

    public AuthenticationPromptEntries createCopy() {
        return new AuthenticationPromptEntries(this);
    }

    public ArrayList<AuthenticationPromptEntry> getPromptEntries() {
        return promptEntries;
    }

    public void setPromptEntries(ArrayList<AuthenticationPromptEntry> promptEntries) {
        this.promptEntries = promptEntries;
    }
}
