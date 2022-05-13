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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;

public class AuthenticationPrompt {

    private ModifiableInteger promptLength;
    private ModifiableString prompt;
    private ModifiableByte echo;

    public AuthenticationPrompt() {}

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
            this.setPromptLength(prompt.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.prompt = prompt;
    }

    public void setPrompt(String prompt, boolean adjustLengthField) {
        if (adjustLengthField) {
            this.setPromptLength(prompt.getBytes(StandardCharsets.UTF_8).length);
        }
        this.prompt = ModifiableVariableFactory.safelySetValue(this.prompt, prompt);
    }

    public ModifiableByte getEcho() {
        return echo;
    }

    public void setEcho(ModifiableByte echo) {
        this.echo = echo;
    }

    public void setEcho(Byte echo) {
        this.echo = ModifiableVariableFactory.safelySetValue(this.echo, echo);
    }

    public void setEcho(boolean echo) {
        setEcho(Converter.booleanToByte(echo));
    }
}
