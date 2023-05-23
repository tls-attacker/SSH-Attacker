/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureFactory;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class UserAuthPubkeyMessagePreparator
        extends UserAuthRequestMessagePreparator<UserAuthPubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPubkeyMessagePreparator(Chooser chooser, UserAuthPubkeyMessage message) {
        super(chooser, message, AuthenticationMethod.PUBLICKEY);
    }

    /* RFC 4252 section 7
    The value of 'signature' is a signature by the corresponding private
    key over the following data, in the following order:

    string    session identifier
    byte      SSH_MSG_USERAUTH_REQUEST
    string    username
    string    service name
    string    "publickey"
    boolean   TRUE
    string    public key algorithm name
    string    public key to be used for authentication */
    private byte[] getSignatureBlob(SshPublicKey<?, ?> pk) {

        // generate the byte array for signing
        // message ID should always be '50'
        // service name should always be 'ssh-connection'
        // use signature should always be 'true'
        try {
            ByteArrayOutputStream signatureOutput = new ByteArrayOutputStream();
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            chooser.getContext().getSessionID().orElse(new byte[0]).length,
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(chooser.getContext().getSessionID().orElse(new byte[0]));
            signatureOutput.write(getObject().getMessageId().getValue());
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            getObject().getUserNameLength().getValue(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(
                    getObject().getUserName().getValue().getBytes(StandardCharsets.UTF_8));
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            getObject().getServiceNameLength().getValue(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(
                    getObject().getServiceName().getValue().getBytes(StandardCharsets.US_ASCII));
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            "publickey".getBytes(StandardCharsets.US_ASCII).length,
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write("publickey".getBytes(StandardCharsets.US_ASCII));
            signatureOutput.write(getObject().getUseSignature().getValue());
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            getObject().getPubkeyAlgNameLength().getValue(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(
                    getObject().getPubkeyAlgName().getValue().getBytes(StandardCharsets.US_ASCII));
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            getObject().getPubkeyLength().getValue(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(getObject().getPubkey().getValue());
            return SignatureFactory.getSigningSignature(
                            PublicKeyAlgorithm.fromName(pk.getPublicKeyFormat().getName()), pk)
                    .sign(signatureOutput.toByteArray());
        } catch (IOException e) {
            LOGGER.error(
                    "An unexpected IOException occurred during signature generation, workflow will continue but "
                            + "signature is left blank");
            LOGGER.debug(e);
            return new byte[0];
        } catch (CryptoException e) {
            LOGGER.error(
                    "An unexpected cryptographic exception occurred during signature generation, workflow will "
                            + "continue but signature is left blank");
            LOGGER.debug(e);
            return new byte[0];
        }
    }

    /* RFC 5656
    3.1.2.  Signature Encoding
    Signatures are encoded as follows:
    string   "ecdsa-sha2-[identifier]"
    string   ecdsa_signature_blob */
    private byte[] getEncodedSignature(SshPublicKey<?, ?> pk) {
        try {
            byte[] signatureBlob = getSignatureBlob(pk);
            ByteArrayOutputStream encodedSignatureOutput = new ByteArrayOutputStream();
            encodedSignatureOutput.write(
                    ArrayConverter.intToBytes(
                            getObject()
                                    .getPubkeyAlgName()
                                    .getValue()
                                    .getBytes(StandardCharsets.US_ASCII)
                                    .length,
                            DataFormatConstants.STRING_SIZE_LENGTH));
            encodedSignatureOutput.write(
                    getObject().getPubkeyAlgName().getValue().getBytes(StandardCharsets.US_ASCII));
            encodedSignatureOutput.write(
                    ArrayConverter.intToBytes(
                            signatureBlob.length, DataFormatConstants.STRING_SIZE_LENGTH));
            encodedSignatureOutput.write(signatureBlob);
            return encodedSignatureOutput.toByteArray();
        } catch (IOException e) {
            LOGGER.error(
                    "An unexpected IOException occurred during signature generation, workflow will continue but "
                            + "signature is left blank");
            LOGGER.debug(e);
            return new byte[0];
        }
    }

    @Override
    public void prepareUserAuthRequestSpecificContents() {
        getObject().setUseSignature(true);
        SshPublicKey<?, ?> pk = chooser.getSelectedPublicKeyForAuthentication();
        if (pk != null) {
            getObject().setPubkeyAlgName(pk.getPublicKeyFormat().getName(), true);
            getObject().setPubkey(PublicKeyHelper.encode(pk), true);
            getObject().setSignature(getEncodedSignature(pk), true);
        } else {
            getObject().setPubkeyAlgName("", true);
            getObject().setPubkey(new byte[0], true);
            getObject().setSignature(new byte[0], true);
        }
    }
}
