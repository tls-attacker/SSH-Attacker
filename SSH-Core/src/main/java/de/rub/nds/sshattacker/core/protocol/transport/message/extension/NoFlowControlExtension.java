/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.NoFlowControlExtensionHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class NoFlowControlExtension extends AbstractExtension<NoFlowControlExtension> {

    private ModifiableInteger choiceLength;
    private ModifiableString choice;

    public NoFlowControlExtension() {
        super();
    }

    public NoFlowControlExtension(NoFlowControlExtension other) {
        super(other);
        choiceLength = other.choiceLength != null ? other.choiceLength.createCopy() : null;
        choice = other.choice != null ? other.choice.createCopy() : null;
    }

    @Override
    public NoFlowControlExtension createCopy() {
        return new NoFlowControlExtension(this);
    }

    public ModifiableInteger getChoiceLength() {
        return choiceLength;
    }

    public void setChoiceLength(ModifiableInteger choiceLength) {
        this.choiceLength = choiceLength;
    }

    public void setChoiceLength(int choiceLength) {
        this.choiceLength =
                ModifiableVariableFactory.safelySetValue(this.choiceLength, choiceLength);
    }

    public ModifiableString getChoice() {
        return choice;
    }

    public void setChoice(ModifiableString choice) {
        setChoice(choice, false);
    }

    public void setChoice(ModifiableString choice, boolean adjustLengthField) {
        if (adjustLengthField) {
            setChoiceLength(choice.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.choice = choice;
    }

    public void setChoice(String choice) {
        setChoice(choice, false);
    }

    public void setChoice(String choice, boolean adjustLengthField) {
        this.choice = ModifiableVariableFactory.safelySetValue(this.choice, choice);
        if (adjustLengthField) {
            setChoiceLength(this.choice.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSoftlyChoice(String choice, boolean adjustLengthField, Config config) {
        if (this.choice == null || this.choice.getOriginalValue() == null) {
            this.choice = ModifiableVariableFactory.safelySetValue(this.choice, choice);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || choiceLength == null
                    || choiceLength.getOriginalValue() == null) {
                setChoiceLength(
                        this.choice.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
    }

    public static final NoFlowControlExtensionHandler HANDLER = new NoFlowControlExtensionHandler();

    @Override
    public NoFlowControlExtensionHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        NoFlowControlExtensionHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return NoFlowControlExtensionHandler.SERIALIZER.serialize(this);
    }
}
