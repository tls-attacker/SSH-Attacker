/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureFactory;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPublicKeyHostboundOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthRequestPublicKeyHostboundOpenSshMessagePreparator
        extends UserAuthRequestMessagePreparator<UserAuthRequestPublicKeyHostboundOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthRequestPublicKeyHostboundOpenSshMessagePreparator(
            Chooser chooser, UserAuthRequestPublicKeyHostboundOpenSshMessage message) {
        super(chooser, message, AuthenticationMethod.PUBLICKEY_HOSTBOUND_V00_OPENSSH_COM);
    }

    private byte[] getSignatureBlob(SshPublicKey<?, ?> publicKey) {
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
                            AuthenticationMethod.PUBLICKEY_HOSTBOUND_V00_OPENSSH_COM
                                    .getName()
                                    .getBytes(StandardCharsets.US_ASCII)
                                    .length,
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(
                    AuthenticationMethod.PUBLICKEY_HOSTBOUND_V00_OPENSSH_COM
                            .getName()
                            .getBytes(StandardCharsets.US_ASCII));
            signatureOutput.write(getObject().getIncludesSignature().getValue());
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            getObject().getPublicKeyAlgorithmNameLength().getValue(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(
                    getObject()
                            .getPublicKeyAlgorithmName()
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII));
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            getObject().getPublicKeyBlobLength().getValue(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(getObject().getPublicKeyBlob().getValue());
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            getObject().getServerHostKeyBlobLength().getValue(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(getObject().getServerHostKeyBlob().getValue());
            return SignatureFactory.getSigningSignature(
                            PublicKeyAlgorithm.fromName(publicKey.getPublicKeyFormat().getName()),
                            publicKey)
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

    private byte[] getEncodedSignature(SshPublicKey<?, ?> publicKey) {
        try {
            byte[] signatureBlob = getSignatureBlob(publicKey);
            ByteArrayOutputStream encodedSignatureOutput = new ByteArrayOutputStream();
            encodedSignatureOutput.write(
                    ArrayConverter.intToBytes(
                            getObject()
                                    .getPublicKeyAlgorithmName()
                                    .getValue()
                                    .getBytes(StandardCharsets.US_ASCII)
                                    .length,
                            DataFormatConstants.STRING_SIZE_LENGTH));
            encodedSignatureOutput.write(
                    getObject()
                            .getPublicKeyAlgorithmName()
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII));
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
        getObject().setIncludesSignature(true);
        SshPublicKey<?, ?> publicKey = chooser.getSelectedPublicKeyForAuthentication();
        SshPublicKey<?, ?> hostKey = chooser.getContext().getHostKey().orElse(null);
        if (publicKey != null && hostKey != null) {
            getObject().setPublicKeyAlgorithmName(publicKey.getPublicKeyFormat().getName(), true);
            getObject().setPublicKeyBlob(PublicKeyHelper.encode(publicKey), true);
            getObject().setServerHostKeyBlob(PublicKeyHelper.encode(hostKey), true);
            getObject().setSignature(getEncodedSignature(publicKey), true);
        } else {
            getObject().setPublicKeyAlgorithmName("", true);
            getObject().setPublicKeyBlob(new byte[0], true);
            getObject().setServerHostKeyBlob(new byte[0], true);
            getObject().setSignature(new byte[0], true);
        }
    }
}
