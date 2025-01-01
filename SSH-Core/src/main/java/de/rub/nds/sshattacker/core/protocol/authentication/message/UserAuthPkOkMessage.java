/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthPkOkMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class UserAuthPkOkMessage extends SshMessage<UserAuthPkOkMessage> {

    private ModifiableInteger pubkeyAlgNameLength;
    private ModifiableString pubkeyAlgName;
    private ModifiableInteger pubkeyLength;
    private ModifiableByteArray pubkey;

    public UserAuthPkOkMessage() {
        super();
    }

    public UserAuthPkOkMessage(UserAuthPkOkMessage other) {
        super(other);
        pubkeyAlgNameLength =
                other.pubkeyAlgNameLength != null ? other.pubkeyAlgNameLength.createCopy() : null;
        pubkeyAlgName = other.pubkeyAlgName != null ? other.pubkeyAlgName.createCopy() : null;
        pubkeyLength = other.pubkeyLength != null ? other.pubkeyLength.createCopy() : null;
        pubkey = other.pubkey != null ? other.pubkey.createCopy() : null;
    }

    @Override
    public UserAuthPkOkMessage createCopy() {
        return new UserAuthPkOkMessage(this);
    }

    public ModifiableInteger getPubkeyAlgNameLength() {
        return pubkeyAlgNameLength;
    }

    public void setPubkeyAlgNameLength(int pubkeyAlgNameLength) {
        this.pubkeyAlgNameLength =
                ModifiableVariableFactory.safelySetValue(
                        this.pubkeyAlgNameLength, pubkeyAlgNameLength);
    }

    public ModifiableString getPubkeyAlgName() {
        return pubkeyAlgName;
    }

    public void setPubkeyAlgName(ModifiableString pubkeyAlgName, boolean adjustLengthField) {
        this.pubkeyAlgName = pubkeyAlgName;
        if (adjustLengthField) {
            setPubkeyAlgNameLength(
                    this.pubkeyAlgName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setPubkeyAlgName(String pubkeyAlgName, boolean adjustLengthField) {
        this.pubkeyAlgName =
                ModifiableVariableFactory.safelySetValue(this.pubkeyAlgName, pubkeyAlgName);
        if (adjustLengthField) {
            setPubkeyAlgNameLength(
                    this.pubkeyAlgName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSoftlyPubkeyAlgName(
            String pubkeyAlgName, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareAuthentication()
                || this.pubkeyAlgName == null
                || this.pubkeyAlgName.getOriginalValue() == null) {
            this.pubkeyAlgName =
                    ModifiableVariableFactory.safelySetValue(this.pubkeyAlgName, pubkeyAlgName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || pubkeyAlgNameLength == null
                    || pubkeyAlgNameLength.getOriginalValue() == null) {
                setPubkeyAlgNameLength(
                        this.pubkeyAlgName.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
    }

    public void setPubkeyAlgName(ModifiableString pubkeyAlgName) {
        setPubkeyAlgName(pubkeyAlgName, false);
    }

    public void setPubkeyAlgName(String pubkeyAlgName) {
        setPubkeyAlgName(pubkeyAlgName, false);
    }

    public void setPubkeyLength(int pubkeyLength) {
        this.pubkeyLength =
                ModifiableVariableFactory.safelySetValue(this.pubkeyLength, pubkeyLength);
    }

    public ModifiableInteger getPubkeyLength() {
        return pubkeyLength;
    }

    public void setPubkey(ModifiableByteArray pubkey, boolean adjustLengthField) {
        this.pubkey = pubkey;
        if (adjustLengthField) {
            setPubkeyLength(this.pubkey.getValue().length);
        }
    }

    public void setPubkey(byte[] pubkey, boolean adjustLengthField) {
        this.pubkey = ModifiableVariableFactory.safelySetValue(this.pubkey, pubkey);
        if (adjustLengthField) {
            setPubkeyLength(this.pubkey.getValue().length);
        }
    }

    public void setSoftlyPubkey(
            byte[] pubkey,
            boolean adjustLengthField,
            Config config,
            boolean useAlwaysPrepareOption) {
        if (useAlwaysPrepareOption && config.getAlwaysPrepareAuthentication()
                || this.pubkey == null
                || this.pubkey.getOriginalValue() == null) {
            this.pubkey = ModifiableVariableFactory.safelySetValue(this.pubkey, pubkey);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || pubkeyLength == null
                    || pubkeyLength.getOriginalValue() == null) {
                setPubkeyLength(this.pubkey.getValue().length);
            }
        }
    }

    public void setPubkey(ModifiableByteArray pubkey) {
        setPubkey(pubkey, false);
    }

    public void setPubkey(byte[] pubkey) {
        setPubkey(pubkey, false);
    }

    public ModifiableByteArray getPubkey() {
        return pubkey;
    }

    public static final UserAuthPkOkMessageHandler HANDLER = new UserAuthPkOkMessageHandler();

    @Override
    public UserAuthPkOkMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UserAuthPkOkMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return UserAuthPkOkMessageHandler.SERIALIZER.serialize(this);
    }
}
