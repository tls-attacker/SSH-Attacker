/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestPtyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ChannelRequestPtyMessage extends ChannelRequestMessage<ChannelRequestPtyMessage> {

    private ModifiableInteger termEnvVariableLength;
    private ModifiableString termEnvVariable;
    private ModifiableInteger widthCharacters;
    private ModifiableInteger heightRows;
    private ModifiableInteger widthPixels;
    private ModifiableInteger heightPixels;
    private ModifiableInteger encodedTerminalModesLength;
    private ModifiableByteArray encodedTerminalModes;

    public ModifiableInteger getTermEnvVariableLength() {
        return termEnvVariableLength;
    }

    public void setTermEnvVariableLength(ModifiableInteger termEnvVariableLength) {
        this.termEnvVariableLength = termEnvVariableLength;
    }

    public void setTermEnvVariableLength(int termEnvVariableLength) {
        this.termEnvVariableLength =
                ModifiableVariableFactory.safelySetValue(
                        this.termEnvVariableLength, termEnvVariableLength);
    }

    public ModifiableString getTermEnvVariable() {
        return termEnvVariable;
    }

    public void setTermEnvVariable(ModifiableString termEnvVariable) {
        this.termEnvVariable = termEnvVariable;
    }

    public void setTermEnvVariable(String termEnvVariable) {
        this.termEnvVariable =
                ModifiableVariableFactory.safelySetValue(this.termEnvVariable, termEnvVariable);
    }

    public void setTermEnvVariable(ModifiableString termEnvVariable, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTermEnvVariableLength(
                    termEnvVariable.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.termEnvVariable = termEnvVariable;
    }

    public void setTermEnvVariable(String termEnvVariable, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTermEnvVariableLength(termEnvVariable.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.termEnvVariable =
                ModifiableVariableFactory.safelySetValue(this.termEnvVariable, termEnvVariable);
    }

    public ModifiableInteger getWidthCharacters() {
        return widthCharacters;
    }

    public void setWidthCharacters(ModifiableInteger widthCharacters) {
        this.widthCharacters = widthCharacters;
    }

    public void setWidthCharacters(int widthCharacters) {
        this.widthCharacters =
                ModifiableVariableFactory.safelySetValue(this.widthCharacters, widthCharacters);
    }

    public ModifiableInteger getHeightRows() {
        return heightRows;
    }

    public void setHeightRows(ModifiableInteger heightRows) {
        this.heightRows = heightRows;
    }

    public void setHeightRows(int heightRows) {
        this.heightRows = ModifiableVariableFactory.safelySetValue(this.heightRows, heightRows);
    }

    public ModifiableInteger getWidthPixels() {
        return widthPixels;
    }

    public void setWidthPixels(ModifiableInteger widthPixels) {
        this.widthPixels = widthPixels;
    }

    public void setWidthPixels(int widthPixels) {
        this.widthPixels = ModifiableVariableFactory.safelySetValue(this.widthPixels, widthPixels);
    }

    public ModifiableInteger getHeightPixels() {
        return heightPixels;
    }

    public void setHeightPixels(ModifiableInteger heightPixels) {
        this.heightPixels = heightPixels;
    }

    public void setHeightPixels(int heightPixels) {
        this.heightPixels =
                ModifiableVariableFactory.safelySetValue(this.heightPixels, heightPixels);
    }

    public ModifiableInteger getEncodedTerminalModesLength() {
        return encodedTerminalModesLength;
    }

    public void setEncodedTerminalModesLength(ModifiableInteger encodedTerminalModesLength) {
        this.encodedTerminalModesLength = encodedTerminalModesLength;
    }

    public void setEncodedTerminalModesLength(int encodedTerminalModesLength) {
        this.encodedTerminalModesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.encodedTerminalModesLength, encodedTerminalModesLength);
    }

    public ModifiableByteArray getEncodedTerminalModes() {
        return encodedTerminalModes;
    }

    public void setEncodedTerminalModes(ModifiableByteArray encodedTerminalModes) {
        this.encodedTerminalModes = encodedTerminalModes;
    }

    public void setEncodedTerminalModes(byte[] encodedTerminalModes) {
        this.encodedTerminalModes =
                ModifiableVariableFactory.safelySetValue(
                        this.encodedTerminalModes, encodedTerminalModes);
    }

    public void setEncodedTerminalModes(
            ModifiableByteArray encodedTerminalModes, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEncodedTerminalModesLength(encodedTerminalModes.getValue().length);
        }
        this.encodedTerminalModes = encodedTerminalModes;
    }

    public void setEncodedTerminalModes(byte[] encodedTerminalModes, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEncodedTerminalModesLength(encodedTerminalModes.length);
        }
        this.encodedTerminalModes =
                ModifiableVariableFactory.safelySetValue(
                        this.encodedTerminalModes, encodedTerminalModes);
    }

    @Override
    public ChannelRequestPtyMessageHandler getHandler(SshContext context) {
        return new ChannelRequestPtyMessageHandler(context, this);
    }
}
