package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthPkOkMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.nio.charset.StandardCharsets;

public class UserAuthPkOkMessage extends SshMessage<UserAuthPkOkMessage> {

    public static final MessageIdConstant ID = MessageIdConstant.SSH_MSG_USERAUTH_PK_OK;
    private ModifiableInteger pubkeyAlgNameLength;
    private ModifiableString pubkeyAlgName;
    private ModifiableInteger pubkeyLength;
    private ModifiableString pubkey;

    public ModifiableInteger getPubkeyAlgNameLength() { return pubkeyAlgNameLength; }

    public void setPubkeyAlgNameLength(int pubkeyAlgNameLength) {
        this.pubkeyAlgNameLength = ModifiableVariableFactory
                .safelySetValue(this.pubkeyAlgNameLength, pubkeyAlgNameLength);
    }

    public ModifiableString getPubkeyAlgName() { return pubkeyAlgName; }

    public void setPubkeyAlgName(ModifiableString pubkeyAlgName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPubkeyAlgNameLength(pubkeyAlgName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.pubkeyAlgName = pubkeyAlgName;
    }

    public void setPubkeyAlgName(String pubkeyAlgName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPubkeyAlgNameLength(pubkeyAlgName.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.pubkeyAlgName = ModifiableVariableFactory.safelySetValue(this.pubkeyAlgName, pubkeyAlgName);
    }

    public void setPubkeyAlgName(ModifiableString pubkeyAlgName) {
        setPubkeyAlgName(pubkeyAlgName, false);
    }

    public void setPubkeyAlgName(String pubkeyAlgName) { setPubkeyAlgName(pubkeyAlgName, false); }

    public ModifiableInteger getPubkeyLength() { return pubkeyLength; }

    public void setPubkeyLength(int pubkeyLength){
        this.pubkeyLength = ModifiableVariableFactory.safelySetValue(this.pubkeyLength, pubkeyLength);
    }

    public ModifiableString getPubkey() { return pubkey; }

    public void setPubkey(ModifiableString pubkey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPubkeyLength(pubkey.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.pubkey = pubkey;
    }

    public void setPubkey(String pubkey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPubkeyLength(pubkey.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.pubkey = ModifiableVariableFactory.safelySetValue(this.pubkey, pubkey);
    }

    public void setPubkey(ModifiableString pubkey) {
        setPubkey(pubkey, false);
    }

    public void setPubkey(String pubkey) { setPubkey(pubkey, false); }

    @Override
    public UserAuthPkOkMessageHandler getHandler(SshContext context) {
        return new UserAuthPkOkMessageHandler(context, this);
    }
}
