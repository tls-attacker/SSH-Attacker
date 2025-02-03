/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.HybridKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class HybridKeyExchangeInitMessage extends SshMessage<HybridKeyExchangeInitMessage>
        implements HasSentHandler {

    private ModifiableInteger concatenatedHybridKeysLength;
    private ModifiableByteArray concatenatedHybridKeys;

    // Neue Variable für die Zertifikatsdaten
    private ModifiableByteArray certificatePublicKeyData;
    private ModifiableInteger certificatePublicKeyDataLength;

    public HybridKeyExchangeInitMessage() {
        super();
    }

    public HybridKeyExchangeInitMessage(HybridKeyExchangeInitMessage other) {
        super(other);
        concatenatedHybridKeysLength =
                other.concatenatedHybridKeysLength != null
                        ? other.concatenatedHybridKeysLength.createCopy()
                        : null;
        concatenatedHybridKeys =
                other.concatenatedHybridKeys != null
                        ? other.concatenatedHybridKeys.createCopy()
                        : null;
        certificatePublicKeyData =
                other.certificatePublicKeyData != null
                        ? other.certificatePublicKeyData.createCopy()
                        : null;
        certificatePublicKeyDataLength =
                other.certificatePublicKeyDataLength != null
                        ? other.certificatePublicKeyDataLength.createCopy()
                        : null;
    }

    @Override
    public HybridKeyExchangeInitMessage createCopy() {
        return new HybridKeyExchangeInitMessage(this);
    }

    public ModifiableInteger getConcatenatedHybridKeysLength() {
        return concatenatedHybridKeysLength;
    }

    public void setConcatenatedHybridKeysLength(ModifiableInteger concatenatedHybridKeysLength) {
        this.concatenatedHybridKeysLength = concatenatedHybridKeysLength;
    }

    public void setConcatenatedHybridKeysLength(int concatenatedHybridKeysLength) {
        this.concatenatedHybridKeysLength =
                ModifiableVariableFactory.safelySetValue(
                        this.concatenatedHybridKeysLength, concatenatedHybridKeysLength);
    }

    public ModifiableByteArray getConcatenatedHybridKeys() {
        return concatenatedHybridKeys;
    }

    public void setConcatenatedHybridKeys(ModifiableByteArray concatenatedHybridKeys) {
        setConcatenatedHybridKeys(concatenatedHybridKeys, false);
    }

    public void setConcatenatedHybridKeys(byte[] concatenatedHybridKeys) {
        setConcatenatedHybridKeys(concatenatedHybridKeys, false);
    }

    public void setConcatenatedHybridKeys(
            ModifiableByteArray concatenatedHybridKeys, boolean adjustLengthField) {
        this.concatenatedHybridKeys = concatenatedHybridKeys;
        if (adjustLengthField) {
            setConcatenatedHybridKeysLength(this.concatenatedHybridKeys.getValue().length);
        }
    }

    public void setConcatenatedHybridKeys(
            byte[] concatenatedHybridKeys, boolean adjustLengthField) {
        this.concatenatedHybridKeys =
                ModifiableVariableFactory.safelySetValue(
                        this.concatenatedHybridKeys, concatenatedHybridKeys);
        if (adjustLengthField) {
            setConcatenatedHybridKeysLength(this.concatenatedHybridKeys.getValue().length);
        }
    }

    public void setSoftlyConcatenatedHybridKeys(
            byte[] concatenatedHybridKeys, boolean adjustLengthField, Config config) {
        this.concatenatedHybridKeys =
                ModifiableVariableFactory.softlySetValue(
                        this.concatenatedHybridKeys,
                        concatenatedHybridKeys,
                        config.getAlwaysPrepareKex());
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || concatenatedHybridKeysLength == null
                    || concatenatedHybridKeysLength.getOriginalValue() == null) {
                setConcatenatedHybridKeysLength(this.concatenatedHybridKeys.getValue().length);
            }
        }
    }

    // Getter und Setter für das Zertifikat
    public ModifiableByteArray getCertificatePublicKeyData() {
        return certificatePublicKeyData;
    }

    public void setCertificatePublicKeyData(ModifiableByteArray certificatePublicKeyData) {
        setCertificatePublicKeyData(certificatePublicKeyData, false);
    }

    public void setCertificatePublicKeyData(byte[] certificatePublicKeyData) {
        setCertificatePublicKeyData(certificatePublicKeyData, false);
    }

    public void setCertificatePublicKeyData(
            ModifiableByteArray certificatePublicKeyData, boolean adjustLengthField) {
        this.certificatePublicKeyData = certificatePublicKeyData;
        if (adjustLengthField) {
            setCertificatePublicKeyDataLength(this.certificatePublicKeyData.getValue().length);
        }
    }

    public void setCertificatePublicKeyData(
            byte[] certificatePublicKeyData, boolean adjustLengthField) {
        this.certificatePublicKeyData =
                ModifiableVariableFactory.safelySetValue(
                        this.certificatePublicKeyData, certificatePublicKeyData);
        if (adjustLengthField) {
            setCertificatePublicKeyDataLength(this.certificatePublicKeyData.getValue().length);
        }
    }

    public void setSoftlyCertificatePublicKeyData(
            byte[] certificatePublicKeyData, boolean adjustLengthField, Config config) {
        this.certificatePublicKeyData =
                ModifiableVariableFactory.softlySetValue(
                        this.certificatePublicKeyData, certificatePublicKeyData);
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || certificatePublicKeyDataLength == null
                    || certificatePublicKeyDataLength.getOriginalValue() == null) {
                setCertificatePublicKeyDataLength(this.certificatePublicKeyData.getValue().length);
            }
        }
    }

    public ModifiableInteger getCertificatePublicKeyDataLength() {
        return certificatePublicKeyDataLength;
    }

    public void setCertificatePublicKeyDataLength(
            ModifiableInteger certificatePublicKeyDataLength) {
        this.certificatePublicKeyDataLength = certificatePublicKeyDataLength;
    }

    public void setCertificatePublicKeyDataLength(int certificatePublicKeyDataLength) {
        this.certificatePublicKeyDataLength =
                ModifiableVariableFactory.safelySetValue(
                        this.certificatePublicKeyDataLength, certificatePublicKeyDataLength);
    }

    public static final HybridKeyExchangeInitMessageHandler HANDLER =
            new HybridKeyExchangeInitMessageHandler();

    @Override
    public HybridKeyExchangeInitMessageHandler getHandler() {
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
        HybridKeyExchangeInitMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return HybridKeyExchangeInitMessageHandler.SERIALIZER.serialize(this);
    }
}
