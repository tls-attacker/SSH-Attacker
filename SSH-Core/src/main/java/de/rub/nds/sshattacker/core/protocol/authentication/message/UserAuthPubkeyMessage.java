package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthPubkeyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

import java.nio.charset.StandardCharsets;

public class UserAuthPubkeyMessage extends UserAuthRequestMessage<UserAuthPubkeyMessage>{

    private ModifiableInteger pubkeyLength;
    private ModifiableByteArray pubkey;
    private ModifiableInteger pubkeyAlgNameLength;
    private ModifiableString pubkeyAlgName;
    private ModifiableByte useSignature;
    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public UserAuthPubkeyMessage() {
        super(AuthenticationMethod.PUBLICKEY);
    }

    public void setPubkeyLength(int pubkeyLength){
        this.pubkeyLength = ModifiableVariableFactory.safelySetValue(this.pubkeyLength, pubkeyLength);
    }

    public ModifiableInteger getPubkeyLength() {
        return pubkeyLength;
    }

    public void setPubkey(ModifiableByteArray pubkey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPubkeyLength(pubkey.getValue().length);
        }
        this.pubkey = pubkey;
    }

    public void setPubkey(byte[] pubkey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPubkeyLength(pubkey.length);
        }
        this.pubkey = ModifiableVariableFactory.safelySetValue(this.pubkey, pubkey);
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

    public void setPubkeyAlgNameLength(int pubkeyAlgNameLength) {
        this.pubkeyAlgNameLength = ModifiableVariableFactory.safelySetValue(this.pubkeyAlgNameLength, pubkeyAlgNameLength);
    }

    public ModifiableInteger getPubkeyAlgNameLength() {
        return pubkeyAlgNameLength;
    }

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

    public void setPubkeyAlgName(String pubkeyAlgName) {
        setPubkeyAlgName(pubkeyAlgName, false);
    }

    public ModifiableString getPubkeyAlgName() {
        return pubkeyAlgName;
    }

    public void setUseSignature(ModifiableByte useSignature) {
        this.useSignature = useSignature;
    }

    public void setUseSignature(byte useSignature) {
        this.useSignature = ModifiableVariableFactory.safelySetValue(this.useSignature, useSignature);
    }

    public void setUseSignature(boolean useSignature) {
        setUseSignature(Converter.booleanToByte(useSignature));
    }

    public ModifiableByte getUseSignature() {
        return useSignature;
    }

    public void setSignatureLength(int signatureLength) {
        this.signatureLength = ModifiableVariableFactory.safelySetValue(this.signatureLength, signatureLength);
    }

    public ModifiableInteger getSignatureLength() {
        return this.signatureLength;
    }

    public void setSignature(ModifiableByteArray signature, boolean adjustLengthField) {
        if (adjustLengthField) {
            setSignatureLength(signature.getValue().length);
        }
        this.signature = signature;
    }

    public void setSignature(byte[] signature, boolean adjustLengthField) {
        if (adjustLengthField) {
            setSignatureLength(signature.length);
        }
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }

    public void setSignature(ModifiableByteArray signature) {
        setSignature(signature, false);
    }

    public void setSignature(byte[] signature) {
        setSignature(signature, false);
    }

    public ModifiableByteArray getSignature() { return signature; }

    @Override
    public UserAuthPubkeyMessageHandler getHandler(SshContext context) {
        return new UserAuthPubkeyMessageHandler(context, this);
    }
}
