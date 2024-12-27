/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.constants.SignatureEncoding;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureFactory;
import de.rub.nds.sshattacker.core.crypto.signature.SigningSignature;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthHostbasedMessagePreparator
        extends UserAuthRequestMessagePreparator<UserAuthHostbasedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthHostbasedMessagePreparator() {
        super(AuthenticationMethod.HOST_BASED);
    }

    @Override
    public void prepareUserAuthRequestSpecificContents(
            UserAuthHostbasedMessage object, Chooser chooser) {

        Config config = chooser.getConfig();
        object.setSoftlyPubKeyAlgorithm(
                chooser.getHostKeyAlgorithm().toString(), true, config);
        object.setSoftlyHostKeyBytes(
                PublicKeyHelper.encode(chooser.getNegotiatedHostKey()), true, config);
        object.setSoftlyHostName(
                Optional.ofNullable(chooser.getContext().getConnection().getIp())
                        .orElse(AliasedConnection.DEFAULT_IP),
                true, config);
        // set the username on client machine to the username on remote, specify if needed
        object.setSoftlyClientUserName(
                config.getUsername(), true, config);
        prepareSignature(object, chooser);
    }

    public static byte[] prepareSignatureInput(UserAuthHostbasedMessage object, Chooser chooser) {
        return ArrayConverter.concatenate(
                Converter.bytesToLengthPrefixedBinaryString(
                        chooser.getContext().getSessionID().orElse(new byte[] {})),
                new byte[] {object.getMessageId().getValue()},
                Converter.stringToLengthPrefixedBinaryString(object.getUserName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(object.getServiceName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(object.getMethodName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(
                        object.getPubKeyAlgorithm().getValue()),
                Converter.bytesToLengthPrefixedBinaryString(object.getHostKeyBytes().getValue()),
                Converter.stringToLengthPrefixedBinaryString(object.getHostName().getValue()),
                Converter.bytesToLengthPrefixedBinaryString(
                        object.getClientUserName().getValue().getBytes(StandardCharsets.UTF_8)));
    }

    public static void prepareSignature(UserAuthHostbasedMessage object, Chooser chooser) {
        SigningSignature signingSignature;
        PublicKeyAlgorithm publicKeyAlgorithm =
                PublicKeyAlgorithm.fromName(object.getPubKeyAlgorithm().getValue());
        try {
            signingSignature =
                    SignatureFactory.getSigningSignature(
                            publicKeyAlgorithm, chooser.getNegotiatedHostKey());
            SignatureEncoding signatureEncoding = publicKeyAlgorithm.getSignatureEncoding();
            ByteArrayOutputStream signatureOutput = new ByteArrayOutputStream();
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            signatureEncoding.getName().length(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(signatureEncoding.getName().getBytes(StandardCharsets.US_ASCII));
            byte[] rawSignature = signingSignature.sign(prepareSignatureInput(object, chooser));
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            rawSignature.length, DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(rawSignature);
            object.setSoftlySignature(signatureOutput.toByteArray(), true, chooser.getConfig());
        } catch (CryptoException e) {
            LOGGER.error(
                    "An unexpected cryptographic exception occurred during signature generation, workflow will continue but signature is left blank");
            LOGGER.debug(e);
            object.setSoftlySignature(new byte[0], true, chooser.getConfig());
        } catch (IOException e) {
            LOGGER.error(
                    "An unexpected IOException occured during signature generation, workflow will continue but signature is left blank");
            LOGGER.debug(e);
            object.setSoftlySignature(new byte[0], true, chooser.getConfig());
        }
    }
}
