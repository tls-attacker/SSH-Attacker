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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.holder.AuthenticationPromptEntryHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import jakarta.xml.bind.annotation.*;
import java.nio.charset.StandardCharsets;

@XmlAccessorType(XmlAccessType.FIELD)
public class AuthenticationPromptEntry extends ModifiableVariableHolder {

    private ModifiableInteger promptLength;
    private ModifiableString prompt;
    private ModifiableByte echo;

    public AuthenticationPromptEntry() {
        super();
    }

    public AuthenticationPromptEntry(AuthenticationPromptEntry other) {
        super(other);
        promptLength = other.promptLength != null ? other.promptLength.createCopy() : null;
        prompt = other.prompt != null ? other.prompt.createCopy() : null;
        echo = other.echo != null ? other.echo.createCopy() : null;
    }

    @Override
    public AuthenticationPromptEntry createCopy() {
        return new AuthenticationPromptEntry(this);
    }

    public ModifiableInteger getPromptLength() {
        return promptLength;
    }

    public void setPromptLength(ModifiableInteger promptLength) {
        this.promptLength = promptLength;
    }

    public void setPromptLength(int promptLength) {
        this.promptLength =
                ModifiableVariableFactory.safelySetValue(this.promptLength, promptLength);
    }

    public ModifiableString getPrompt() {
        return prompt;
    }

    public void setPrompt(ModifiableString prompt) {
        this.prompt = prompt;
    }

    public void setPrompt(String prompt) {
        this.prompt = ModifiableVariableFactory.safelySetValue(this.prompt, prompt);
    }

    public void setPrompt(ModifiableString prompt, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPromptLength(prompt.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.prompt = prompt;
    }

    public void setPrompt(String prompt, boolean adjustLengthField) {
        this.prompt = ModifiableVariableFactory.safelySetValue(this.prompt, prompt);
        if (adjustLengthField) {
            setPromptLength(this.prompt.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyPrompt(String prompt, boolean adjustLengthField, Config config) {
        if (this.prompt == null || this.prompt.getOriginalValue() == null) {
            this.prompt = ModifiableVariableFactory.safelySetValue(this.prompt, prompt);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || promptLength == null
                    || promptLength.getOriginalValue() == null) {
                setPromptLength(this.prompt.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    public ModifiableByte getEcho() {
        return echo;
    }

    public void setEcho(ModifiableByte echo) {
        this.echo = echo;
    }

    public void setEcho(byte echo) {
        this.echo = ModifiableVariableFactory.safelySetValue(this.echo, echo);
    }

    public void setSoftlyEcho(byte echo) {
        if (this.echo == null || this.echo.getOriginalValue() == null) {
            this.echo = ModifiableVariableFactory.safelySetValue(this.echo, echo);
        }
    }

    public void setEcho(boolean echo) {
        setEcho(Converter.booleanToByte(echo));
    }

    public void setSoftlyEcho(boolean echo) {
        setSoftlyEcho(Converter.booleanToByte(echo));
    }

    public AuthenticationPromptEntryHandler getHandler(SshContext context) {
        return new AuthenticationPromptEntryHandler(context, this);
    }
}
