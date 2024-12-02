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
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.HybridKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class HybridKeyExchangeInitMessage extends SshMessage<HybridKeyExchangeInitMessage> {

    private ModifiableInteger agreementPublicKeyLength;
    private ModifiableByteArray agreementPublicKey;
    private ModifiableInteger encapsulationPublicKeyLength;
    private ModifiableByteArray encapsulationPublicKey;

    // Neue Variable für die Zertifikatsdaten
    private ModifiableByteArray certificatePublicKeyData;
    private ModifiableInteger certificatePublicKeyDataLength;

    public HybridKeyExchangeInitMessage() {
        super();
    }

    public HybridKeyExchangeInitMessage(HybridKeyExchangeInitMessage other) {
        super(other);
        agreementPublicKeyLength =
                other.agreementPublicKeyLength != null
                        ? other.agreementPublicKeyLength.createCopy()
                        : null;
        agreementPublicKey =
                other.agreementPublicKey != null ? other.agreementPublicKey.createCopy() : null;
        encapsulationPublicKeyLength =
                other.encapsulationPublicKeyLength != null
                        ? other.encapsulationPublicKeyLength.createCopy()
                        : null;
        encapsulationPublicKey =
                other.encapsulationPublicKey != null
                        ? other.encapsulationPublicKey.createCopy()
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

    public ModifiableInteger getAgreementPublicKeyLength() {
        return agreementPublicKeyLength;
    }

    public void setAgreementPublicKeyLength(ModifiableInteger agreementPublicKeyLength) {
        this.agreementPublicKeyLength = agreementPublicKeyLength;
    }

    public void setAgreementPublicKeyLength(int agreementPublicKeyLength) {
        this.agreementPublicKeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.agreementPublicKeyLength, agreementPublicKeyLength);
    }

    public ModifiableByteArray getAgreementPublicKey() {
        return agreementPublicKey;
    }

    public void setAgreementPublicKey(ModifiableByteArray agreementPublicKey) {
        setAgreementPublicKey(agreementPublicKey, false);
    }

    public void setAgreementPublicKey(byte[] agreementPublicKey) {
        setAgreementPublicKey(agreementPublicKey, false);
    }

    public void setAgreementPublicKey(
            ModifiableByteArray agreementPublicKey, boolean adjustLengthField) {
        this.agreementPublicKey = agreementPublicKey;
        if (adjustLengthField) {
            setAgreementPublicKeyLength(this.agreementPublicKey.getValue().length);
        }
    }

    public void setAgreementPublicKey(byte[] agreementPublicKey, boolean adjustLengthField) {
        this.agreementPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.agreementPublicKey, agreementPublicKey);
        if (adjustLengthField) {
            setAgreementPublicKeyLength(this.agreementPublicKey.getValue().length);
        }
    }

    public void setSoftlyAgreementPublicKey(
            byte[] agreementPublicKey, boolean adjustLengthField, Config config) {
        if (this.agreementPublicKey == null || this.agreementPublicKey.getOriginalValue() == null) {
            this.agreementPublicKey =
                    ModifiableVariableFactory.safelySetValue(
                            this.agreementPublicKey, agreementPublicKey);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || agreementPublicKeyLength == null
                    || agreementPublicKeyLength.getOriginalValue() == null) {
                setAgreementPublicKeyLength(this.agreementPublicKey.getValue().length);
            }
        }
    }

    public ModifiableInteger getEncapsulationPublicKeyLength() {
        return encapsulationPublicKeyLength;
    }

    public void setEncapsulationPublicKeyLength(ModifiableInteger encapsulationPublicKeyLength) {
        this.encapsulationPublicKeyLength = encapsulationPublicKeyLength;
    }

    public void setEncapsulationPublicKeyLength(int encapsulationPublicKeyLength) {
        this.encapsulationPublicKeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.encapsulationPublicKeyLength, encapsulationPublicKeyLength);
    }

    public ModifiableByteArray getEncapsulationPublicKey() {
        return encapsulationPublicKey;
    }

    public void setEncapsulationPublicKey(ModifiableByteArray encapsulationPublicKey) {
        setEncapsulationPublicKey(encapsulationPublicKey, false);
    }

    public void setEncapsulationPublicKey(byte[] encapsulationPublicKey) {
        setEncapsulationPublicKey(encapsulationPublicKey, false);
    }

    public void setEncapsulationPublicKey(
            ModifiableByteArray encapsulationPublicKey, boolean adjustLengthField) {
        this.encapsulationPublicKey = encapsulationPublicKey;
        if (adjustLengthField) {
            setEncapsulationPublicKeyLength(this.encapsulationPublicKey.getValue().length);
        }
    }

    public void setEncapsulationPublicKey(
            byte[] encapsulationPublicKey, boolean adjustLengthField) {
        this.encapsulationPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.encapsulationPublicKey, encapsulationPublicKey);
        if (adjustLengthField) {
            setEncapsulationPublicKeyLength(this.encapsulationPublicKey.getValue().length);
        }
    }

    public void setSoftlyEncapsulationPublicKey(
            byte[] encapsulationPublicKey, boolean adjustLengthField, Config config) {
        if (this.encapsulationPublicKey == null
                || this.encapsulationPublicKey.getOriginalValue() == null) {
            this.encapsulationPublicKey =
                    ModifiableVariableFactory.safelySetValue(
                            this.encapsulationPublicKey, encapsulationPublicKey);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || encapsulationPublicKeyLength == null
                    || encapsulationPublicKeyLength.getOriginalValue() == null) {
                setEncapsulationPublicKeyLength(this.encapsulationPublicKey.getValue().length);
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
        if (this.certificatePublicKeyData == null
                || this.certificatePublicKeyData.getOriginalValue() == null) {
            this.certificatePublicKeyData =
                    ModifiableVariableFactory.safelySetValue(
                            this.certificatePublicKeyData, certificatePublicKeyData);
        }
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

    @Override
    public SshMessageHandler<HybridKeyExchangeInitMessage> getHandler(SshContext context) {
        return new HybridKeyExchangeInitMessageHandler(context, this);
    }
}
