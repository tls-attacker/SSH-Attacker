/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.PublicKeyAlgorithmsRoumenPetrovExtensionHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class PublicKeyAlgorithmsRoumenPetrovExtension
        extends AbstractExtension<PublicKeyAlgorithmsRoumenPetrovExtension> {

    private ModifiableInteger publicKeyAlgorithmsLength;
    private ModifiableString publicKeyAlgorithms;

    public PublicKeyAlgorithmsRoumenPetrovExtension() {
        super();
    }

    public PublicKeyAlgorithmsRoumenPetrovExtension(
            PublicKeyAlgorithmsRoumenPetrovExtension other) {
        super(other);
        publicKeyAlgorithmsLength =
                other.publicKeyAlgorithmsLength != null
                        ? other.publicKeyAlgorithmsLength.createCopy()
                        : null;
        publicKeyAlgorithms =
                other.publicKeyAlgorithms != null ? other.publicKeyAlgorithms.createCopy() : null;
    }

    @Override
    public PublicKeyAlgorithmsRoumenPetrovExtension createCopy() {
        return new PublicKeyAlgorithmsRoumenPetrovExtension(this);
    }

    public ModifiableInteger getPublicKeyAlgorithmsLength() {
        return publicKeyAlgorithmsLength;
    }

    public void setPublicKeyAlgorithmsLength(ModifiableInteger publicKeyAlgorithmsLength) {
        this.publicKeyAlgorithmsLength = publicKeyAlgorithmsLength;
    }

    public void setPublicKeyAlgorithmsLength(int publicKeyAlgorithmsLength) {
        this.publicKeyAlgorithmsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.publicKeyAlgorithmsLength, publicKeyAlgorithmsLength);
    }

    public ModifiableString getPublicKeyAlgorithms() {
        return publicKeyAlgorithms;
    }

    public void setPublicKeyAlgorithms(ModifiableString publicKeyAlgorithms) {
        setPublicKeyAlgorithms(publicKeyAlgorithms, false);
    }

    public void setPublicKeyAlgorithms(String publicKeyAlgorithms) {
        setPublicKeyAlgorithms(publicKeyAlgorithms, false);
    }

    public void setPublicKeyAlgorithms(String[] publicKeyAlgorithms) {
        setPublicKeyAlgorithms(publicKeyAlgorithms, false);
    }

    public void setPublicKeyAlgorithms(List<PublicKeyAlgorithm> publicKeyAlgorithms) {
        setPublicKeyAlgorithms(publicKeyAlgorithms, false);
    }

    public void setPublicKeyAlgorithms(
            ModifiableString publicKeyAlgorithms, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPublicKeyAlgorithmsLength(
                    publicKeyAlgorithms.getValue().getBytes(StandardCharsets.US_ASCII).length);
            setPublicKeyAlgorithmsLength(publicKeyAlgorithmsLength.getValue());
        }
        this.publicKeyAlgorithms = publicKeyAlgorithms;
    }

    public void setPublicKeyAlgorithms(String publicKeyAlgorithms, boolean adjustLengthField) {
        this.publicKeyAlgorithms =
                ModifiableVariableFactory.safelySetValue(
                        this.publicKeyAlgorithms, publicKeyAlgorithms);
        if (adjustLengthField) {
            setPublicKeyAlgorithmsLength(
                    this.publicKeyAlgorithms.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setPublicKeyAlgorithms(String[] publicKeyAlgorithms, boolean adjustLengthField) {
        setPublicKeyAlgorithms(
                Converter.listOfNamesToString(publicKeyAlgorithms), adjustLengthField);
    }

    public void setPublicKeyAlgorithms(
            List<PublicKeyAlgorithm> publicKeyAlgorithms, boolean adjustLengthField) {
        setPublicKeyAlgorithms(
                Converter.listOfNamesToString(publicKeyAlgorithms), adjustLengthField);
    }

    public void setSoftlyPublicKeyAlgorithms(
            List<PublicKeyAlgorithm> publicKeyAlgorithms,
            boolean adjustLengthField,
            Config config) {

        if (this.publicKeyAlgorithms == null
                || this.publicKeyAlgorithms.getOriginalValue() == null) {
            this.publicKeyAlgorithms =
                    ModifiableVariableFactory.safelySetValue(
                            this.publicKeyAlgorithms,
                            Converter.listOfNamesToString(publicKeyAlgorithms));
        }

        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || publicKeyAlgorithmsLength == null
                    || publicKeyAlgorithmsLength.getOriginalValue() == null) {
                setPublicKeyAlgorithmsLength(
                        this.publicKeyAlgorithms
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public static final PublicKeyAlgorithmsRoumenPetrovExtensionHandler HANDLER =
            new PublicKeyAlgorithmsRoumenPetrovExtensionHandler();

    @Override
    public PublicKeyAlgorithmsRoumenPetrovExtensionHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        PublicKeyAlgorithmsRoumenPetrovExtensionHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return PublicKeyAlgorithmsRoumenPetrovExtensionHandler.SERIALIZER.serialize(this);
    }
}
