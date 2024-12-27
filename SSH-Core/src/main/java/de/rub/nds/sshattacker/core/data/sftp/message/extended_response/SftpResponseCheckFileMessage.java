/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.HashAlgorithm;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_response.SftpResponseCheckFileMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class SftpResponseCheckFileMessage
        extends SftpResponseMessage<SftpResponseCheckFileMessage> {
    private ModifiableInteger usedHashAlgorithmLength;
    private ModifiableString usedHashAlgorithm;
    private ModifiableByteArray hash;

    public SftpResponseCheckFileMessage() {
        super();
    }

    public SftpResponseCheckFileMessage(SftpResponseCheckFileMessage other) {
        super(other);
        usedHashAlgorithmLength =
                other.usedHashAlgorithmLength != null
                        ? other.usedHashAlgorithmLength.createCopy()
                        : null;
        usedHashAlgorithm =
                other.usedHashAlgorithm != null ? other.usedHashAlgorithm.createCopy() : null;
        hash = other.hash != null ? other.hash.createCopy() : null;
    }

    @Override
    public SftpResponseCheckFileMessage createCopy() {
        return new SftpResponseCheckFileMessage(this);
    }

    public ModifiableInteger getUsedHashAlgorithmLength() {
        return usedHashAlgorithmLength;
    }

    public void setUsedHashAlgorithmLength(ModifiableInteger usedHashAlgorithmLength) {
        this.usedHashAlgorithmLength = usedHashAlgorithmLength;
    }

    public void setUsedHashAlgorithmLength(int usedHashAlgorithmLength) {
        this.usedHashAlgorithmLength =
                ModifiableVariableFactory.safelySetValue(
                        this.usedHashAlgorithmLength, usedHashAlgorithmLength);
    }

    public ModifiableString getUsedHashAlgorithm() {
        return usedHashAlgorithm;
    }

    public void setUsedHashAlgorithm(ModifiableString usedHashAlgorithm) {
        setUsedHashAlgorithm(usedHashAlgorithm, false);
    }

    public void setUsedHashAlgorithm(String usedHashAlgorithm) {
        setUsedHashAlgorithm(usedHashAlgorithm, false);
    }

    public void setUsedHashAlgorithm(HashAlgorithm usedHashAlgorithm) {
        setUsedHashAlgorithm(usedHashAlgorithm.getName(), false);
    }

    public void setUsedHashAlgorithm(
            ModifiableString usedHashAlgorithm, boolean adjustLengthField) {
        if (adjustLengthField) {
            setUsedHashAlgorithmLength(
                    usedHashAlgorithm.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.usedHashAlgorithm = usedHashAlgorithm;
    }

    public void setUsedHashAlgorithm(String usedHashAlgorithm, boolean adjustLengthField) {
        this.usedHashAlgorithm =
                ModifiableVariableFactory.safelySetValue(this.usedHashAlgorithm, usedHashAlgorithm);
        if (adjustLengthField) {
            setUsedHashAlgorithmLength(
                    this.usedHashAlgorithm.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSoftlyUsedHashAlgorithm(
            String usedHashAlgorithm, boolean adjustLengthField, Config config) {
        if (this.usedHashAlgorithm == null || this.usedHashAlgorithm.getOriginalValue() == null) {
            this.usedHashAlgorithm =
                    ModifiableVariableFactory.safelySetValue(
                            this.usedHashAlgorithm, usedHashAlgorithm);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || usedHashAlgorithmLength == null
                    || usedHashAlgorithmLength.getOriginalValue() == null) {
                setUsedHashAlgorithmLength(
                        this.usedHashAlgorithm
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setUsedHashAlgorithm(HashAlgorithm usedHashAlgorithm, boolean adjustLengthField) {
        setUsedHashAlgorithm(usedHashAlgorithm.getName(), adjustLengthField);
    }

    public void setSoftlyUsedHashAlgorithm(
            HashAlgorithm usedHashAlgorithm, boolean adjustLengthField, Config config) {
        setSoftlyUsedHashAlgorithm(usedHashAlgorithm.getName(), adjustLengthField, config);
    }

    public ModifiableByteArray getHash() {
        return hash;
    }

    public void setHash(ModifiableByteArray hash) {
        this.hash = hash;
    }

    public void setHash(byte[] hash) {
        this.hash = ModifiableVariableFactory.safelySetValue(this.hash, hash);
    }

    public void setSoftlyHash(byte[] hash) {
        if (this.hash == null || this.hash.getOriginalValue() == null) {
            this.hash = ModifiableVariableFactory.safelySetValue(this.hash, hash);
        }
    }

    @Override
    public SftpResponseCheckFileMessageHandler getHandler(SshContext context) {
        return new SftpResponseCheckFileMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpResponseCheckFileMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpResponseCheckFileMessageHandler.SERIALIZER.serialize(this);
    }
}
