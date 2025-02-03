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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestPtyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class ChannelRequestPtyMessage extends ChannelRequestMessage<ChannelRequestPtyMessage>
        implements HasSentHandler {

    private ModifiableInteger termEnvVariableLength;
    private ModifiableString termEnvVariable;
    private ModifiableInteger widthCharacters;
    private ModifiableInteger heightRows;
    private ModifiableInteger widthPixels;
    private ModifiableInteger heightPixels;
    private ModifiableInteger encodedTerminalModesLength;
    private ModifiableByteArray encodedTerminalModes;

    public ChannelRequestPtyMessage() {
        super();
    }

    public ChannelRequestPtyMessage(ChannelRequestPtyMessage other) {
        super(other);
        termEnvVariableLength =
                other.termEnvVariableLength != null
                        ? other.termEnvVariableLength.createCopy()
                        : null;
        termEnvVariable = other.termEnvVariable != null ? other.termEnvVariable.createCopy() : null;
        widthCharacters = other.widthCharacters != null ? other.widthCharacters.createCopy() : null;
        heightRows = other.heightRows != null ? other.heightRows.createCopy() : null;
        widthPixels = other.widthPixels != null ? other.widthPixels.createCopy() : null;
        heightPixels = other.heightPixels != null ? other.heightPixels.createCopy() : null;
        encodedTerminalModesLength =
                other.encodedTerminalModesLength != null
                        ? other.encodedTerminalModesLength.createCopy()
                        : null;
        encodedTerminalModes =
                other.encodedTerminalModes != null ? other.encodedTerminalModes.createCopy() : null;
    }

    @Override
    public ChannelRequestPtyMessage createCopy() {
        return new ChannelRequestPtyMessage(this);
    }

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
        this.termEnvVariable = termEnvVariable;
        if (adjustLengthField) {
            setTermEnvVariableLength(
                    this.termEnvVariable.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setTermEnvVariable(String termEnvVariable, boolean adjustLengthField) {
        this.termEnvVariable =
                ModifiableVariableFactory.safelySetValue(this.termEnvVariable, termEnvVariable);
        if (adjustLengthField) {
            setTermEnvVariableLength(
                    this.termEnvVariable.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSoftlyTermEnvVariable(
            String termEnvVariable, boolean adjustLengthField, Config config) {
        this.termEnvVariable =
                ModifiableVariableFactory.softlySetValue(this.termEnvVariable, termEnvVariable);
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || termEnvVariableLength == null
                    || termEnvVariableLength.getOriginalValue() == null) {
                setTermEnvVariableLength(
                        this.termEnvVariable.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
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

    public void setSoftlyWidthCharacters(int widthCharacters) {
        this.widthCharacters =
                ModifiableVariableFactory.softlySetValue(this.widthCharacters, widthCharacters);
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

    public void setSoftlyHeightRows(int heightRows) {
        this.heightRows = ModifiableVariableFactory.softlySetValue(this.heightRows, heightRows);
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

    public void setSoftlyWidthPixels(int widthPixels) {
        this.widthPixels = ModifiableVariableFactory.softlySetValue(this.widthPixels, widthPixels);
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

    public void setSoftlyHeightPixels(int heightPixels) {
        this.heightPixels =
                ModifiableVariableFactory.softlySetValue(this.heightPixels, heightPixels);
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
        this.encodedTerminalModes = encodedTerminalModes;
        if (adjustLengthField) {
            setEncodedTerminalModesLength(this.encodedTerminalModes.getValue().length);
        }
    }

    public void setEncodedTerminalModes(byte[] encodedTerminalModes, boolean adjustLengthField) {
        this.encodedTerminalModes =
                ModifiableVariableFactory.safelySetValue(
                        this.encodedTerminalModes, encodedTerminalModes);
        if (adjustLengthField) {
            setEncodedTerminalModesLength(this.encodedTerminalModes.getValue().length);
        }
    }

    public void setSoftlyEncodedTerminalModes(
            byte[] encodedTerminalModes, boolean adjustLengthField, Config config) {
        this.encodedTerminalModes =
                ModifiableVariableFactory.softlySetValue(
                        this.encodedTerminalModes, encodedTerminalModes);
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || encodedTerminalModesLength == null
                    || encodedTerminalModesLength.getOriginalValue() == null) {
                setEncodedTerminalModesLength(this.encodedTerminalModes.getValue().length);
            }
        }
    }

    public static final ChannelRequestPtyMessageHandler HANDLER =
            new ChannelRequestPtyMessageHandler();

    @Override
    public ChannelRequestPtyMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelRequestPtyMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestPtyMessageHandler.SERIALIZER.serialize(this);
    }
}
