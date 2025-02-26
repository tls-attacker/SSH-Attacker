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
import de.rub.nds.sshattacker.core.protocol.authentication.handler.holder.AuthenticationPromptEntryHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class AuthenticationPromptEntry extends ModifiableVariableHolder {

    private ModifiableInteger promptLength;
    private ModifiableString prompt;
    private ModifiableByte echo;

    public AuthenticationPromptEntry() {
        super();
    }

    public AuthenticationPromptEntry(String prompt, boolean echo) {
        super();
        setPrompt(prompt, true);
        setEcho(echo);
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

    public ModifiableByte getEcho() {
        return echo;
    }

    public void setEcho(ModifiableByte echo) {
        this.echo = echo;
    }

    public void setEcho(byte echo) {
        this.echo = ModifiableVariableFactory.safelySetValue(this.echo, echo);
    }

    public void setEcho(boolean echo) {
        setEcho(Converter.booleanToByte(echo));
    }

    public static final AuthenticationPromptEntryHandler HANDLER =
            new AuthenticationPromptEntryHandler();

    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    public void prepare(Chooser chooser) {
        AuthenticationPromptEntryHandler.PREPARATOR.prepare(this, chooser);
    }

    public byte[] serialize() {
        return AuthenticationPromptEntryHandler.SERIALIZER.serialize(this);
    }
}
