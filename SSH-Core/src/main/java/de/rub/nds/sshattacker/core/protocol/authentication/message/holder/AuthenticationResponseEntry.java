/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message.holder;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.holder.AuthenticationResponseEntryHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.*;
import java.nio.charset.StandardCharsets;

@XmlAccessorType(XmlAccessType.FIELD)
public class AuthenticationResponseEntry extends ModifiableVariableHolder {

    private ModifiableInteger responseLength;
    private ModifiableString response;

    public AuthenticationResponseEntry() {
        super();
    }

    public AuthenticationResponseEntry(String response) {
        super();
        setResponse(response, true);
    }

    public AuthenticationResponseEntry(AuthenticationResponseEntry other) {
        super(other);
        responseLength = other.responseLength != null ? other.responseLength.createCopy() : null;
        response = other.response != null ? other.response.createCopy() : null;
    }

    @Override
    public AuthenticationResponseEntry createCopy() {
        return new AuthenticationResponseEntry(this);
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
        this.response = ModifiableVariableFactory.safelySetValue(this.response, response);
        if (adjustLengthField) {
            setResponseLength(this.response.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyResponse(String response, boolean adjustLengthField, Config config) {
        if (this.response == null || this.response.getOriginalValue() == null) {
            this.response = ModifiableVariableFactory.safelySetValue(this.response, response);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || responseLength == null
                    || responseLength.getOriginalValue() == null) {
                setResponseLength(this.response.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    public AuthenticationResponseEntryHandler getHandler(SshContext context) {
        return new AuthenticationResponseEntryHandler(context, this);
    }
}
