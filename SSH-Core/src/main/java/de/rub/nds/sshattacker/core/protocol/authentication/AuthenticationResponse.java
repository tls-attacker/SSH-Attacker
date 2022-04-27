/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;

public class AuthenticationResponse implements Serializable {

    private ModifiableInteger responseLength;
    private ModifiableString response;
    private boolean executed;

    public AuthenticationResponse() {}

    public AuthenticationResponse(boolean executed) {
        setExecuted(executed);
    }

    public AuthenticationResponse(String response, boolean executed) {
        setResponse(response, true);
        setExecuted(executed);
    }

    public ModifiableInteger getResponseLength() {
        return responseLength;
    }

    public void setResponseLength(ModifiableInteger responseLength) {
        this.responseLength = responseLength;
    }

    public void setResponseLength(int responseLength) {
        this.responseLength =
                ModifiableVariableFactory.safelySetValue(this.responseLength, responseLength);
    }

    public ModifiableString getResponse() {
        return response;
    }

    public void setResponse(ModifiableString response) {
        this.response = response;
    }

    public void setResponse(String response) {
        this.response = ModifiableVariableFactory.safelySetValue(this.response, response);
    }

    public void setResponse(ModifiableString response, boolean adjustLengthField) {
        if (adjustLengthField) {
            setResponseLength(response.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.response = response;
    }

    public void setResponse(String response, boolean adjustLengthField) {
        if (adjustLengthField) {
            setResponseLength(response.getBytes(StandardCharsets.UTF_8).length);
        }
        this.response = ModifiableVariableFactory.safelySetValue(this.response, response);
    }

    public boolean isExecuted() {
        return executed;
    }

    public void setExecuted(boolean executed) {
        this.executed = executed;
    }
}
