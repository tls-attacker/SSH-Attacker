/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureFactory;
import de.rub.nds.sshattacker.core.crypto.signature.SigningSignature;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthHostbasedMessagePreperator
        extends SshMessagePreparator<UserAuthHostbasedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthHostbasedMessagePreperator(Chooser chooser, UserAuthHostbasedMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setUserName(chooser.getConfig().getUsername(), true);
        getObject().setServiceName(ServiceType.SSH_CONNECTION, true);
        getObject().setMethodName(AuthenticationMethod.HOST_BASED, true);
        getObject().setPubKeyAlgorithm(chooser.getServerHostKeyAlgorithm().toString(), true);
        getObject()
                .setHostKeyBytes(
                        PublicKeyHelper.encode(chooser.getNegotiatedServerHostKey()), true);
        Optional<String> hostName =
                Optional.ofNullable(chooser.getContext().getConnection().getIp());
        getObject().setHostName(hostName.orElse(AliasedConnection.DEFAULT_IP), true);
        // set the user name on client machine to the username on remote, specify if needed
        getObject().setClientUserName(chooser.getConfig().getUsername(), true);
        prepareSignature();
    }

    public byte[] prepareSignatureInput() {
        return ArrayConverter.concatenate(
                Converter.bytesToLengthPrefixedBinaryString(
                        chooser.getContext().getSessionID().orElse(new byte[] {})),
                new byte[] {getObject().getMessageId().getValue().byteValue()},
                Converter.stringToLengthPrefixedBinaryString(getObject().getUserName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(
                        getObject().getServiceName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(
                        getObject().getMethodName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(
                        getObject().getPubKeyAlgorithm().getValue()),
                Converter.bytesToLengthPrefixedBinaryString(
                        getObject().getHostKeyBytes().getValue()),
                Converter.stringToLengthPrefixedBinaryString(getObject().getHostName().getValue()),
                Converter.bytesToLengthPrefixedBinaryString(
                        getObject()
                                .getClientUserName()
                                .getValue()
                                .getBytes(StandardCharsets.UTF_8)));
    }

    public void prepareSignature() {
        SigningSignature signingSignature;
        PublicKeyAlgorithm publicKeyAlgorithm =
                PublicKeyAlgorithm.fromName(getObject().getPubKeyAlgorithm().getValue());
        try {
            signingSignature =
                    SignatureFactory.getSigningSignature(
                            publicKeyAlgorithm, chooser.getNegotiatedServerHostKey());
            SignatureEncoding signatureEncoding = publicKeyAlgorithm.getSignatureEncoding();
            ByteArrayOutputStream signatureOutput = new ByteArrayOutputStream();
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            signatureEncoding.getName().length(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(signatureEncoding.getName().getBytes(StandardCharsets.US_ASCII));
            byte[] rawSignature = signingSignature.sign(this.prepareSignatureInput());
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            rawSignature.length, DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(rawSignature);
            getObject().setSignature(signatureOutput.toByteArray(), true);
        } catch (CryptoException e) {
            LOGGER.error(
                    "An unexpected cryptographic exception occurred during signature generation, workflow will continue but signature is left blank");
            LOGGER.debug(e);
            getObject().setSignature(new byte[0], true);
        } catch (IOException e) {
            LOGGER.error(
                    "An unexpected IOException occured during signature generation, workflow will continue but signature is left blank");
            LOGGER.debug(e);
            getObject().setSignature(new byte[0], true);
        }
    }
}
