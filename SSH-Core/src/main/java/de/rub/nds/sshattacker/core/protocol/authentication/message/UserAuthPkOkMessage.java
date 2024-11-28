/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthPkOkMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class UserAuthPkOkMessage extends SshMessage<UserAuthPkOkMessage> {

    private ModifiableInteger pubkeyAlgNameLength;
    private ModifiableString pubkeyAlgName;
    private ModifiableInteger pubkeyLength;
    private ModifiableString pubkey;

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
        if (this.pubkeyAlgName == null || this.pubkeyAlgName.getOriginalValue() == null) {
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

    public ModifiableInteger getPubkeyLength() {
        return pubkeyLength;
    }

    public void setPubkeyLength(int pubkeyLength) {
        this.pubkeyLength =
                ModifiableVariableFactory.safelySetValue(this.pubkeyLength, pubkeyLength);
    }

    public ModifiableString getPubkey() {
        return pubkey;
    }

    public void setPubkey(ModifiableString pubkey, boolean adjustLengthField) {
        this.pubkey = pubkey;
        if (adjustLengthField) {
            setPubkeyLength(this.pubkey.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setPubkey(String pubkey, boolean adjustLengthField) {
        this.pubkey = ModifiableVariableFactory.safelySetValue(this.pubkey, pubkey);
        if (adjustLengthField) {
            setPubkeyLength(this.pubkey.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSoftlyPubkey(String pubkey, boolean adjustLengthField, Config config) {
        if (this.pubkey == null || this.pubkey.getOriginalValue() == null) {
            this.pubkey = ModifiableVariableFactory.safelySetValue(this.pubkey, pubkey);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || pubkeyLength == null
                    || pubkeyLength.getOriginalValue() == null) {
                setPubkeyLength(this.pubkey.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
    }

    public void setPubkey(ModifiableString pubkey) {
        setPubkey(pubkey, false);
    }

    public void setPubkey(String pubkey) {
        setPubkey(pubkey, false);
    }

    @Override
    public UserAuthPkOkMessageHandler getHandler(SshContext context) {
        return new UserAuthPkOkMessageHandler(context, this);
    }
}
