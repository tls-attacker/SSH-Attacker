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
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthPkOkMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthPkOkMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.io.InputStream;
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

    public void setPubkey(ModifiableString pubkey) {
        setPubkey(pubkey, false);
    }

    public void setPubkey(String pubkey) {
        setPubkey(pubkey, false);
    }

    @Override
    public UserAuthPkOkMessageHandler getHandler(SshContext context) {
        return new UserAuthPkOkMessageHandler(context);
    }

    @Override
    public UserAuthPkOkMessageParser getParser(SshContext context, InputStream stream) {
        return new UserAuthPkOkMessageParser(stream);
    }

    @Override
    public SshMessagePreparator<UserAuthPkOkMessage> getPreparator(SshContext context) {
        throw new NotImplementedException("UserAuthPkOkMessageHandler::getPreparator");
    }

    @Override
    public SshMessageSerializer<UserAuthPkOkMessage> getSerializer(SshContext context) {
        throw new NotImplementedException("UserAuthPkOkMessageHandler::getSerializer");
    }

    @Override
    public String toShortString() {
        return "USERAUTH_PK_OK";
    }
}
