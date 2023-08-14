/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.constants.SignatureEncoding;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureFactory;
import de.rub.nds.sshattacker.core.crypto.signature.SigningSignature;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysProveSuccessMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class OpenSshHostKeyHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Encodes a list of keys into a host key blob value, consisting of one length-prefixed string
     * per key.
     *
     * @param keys the list of keys to encode
     * @return the encoded key blob
     */
    public static byte[] encodeKeys(List<SshPublicKey<?, ?>> keys) {
        for (SshPublicKey<?, ?> sshPublicKey : keys) {
            LOGGER.info("Encoding key " + sshPublicKey);
        }
        return keys.stream()
                .map(PublicKeyHelper::encode)
                .map(Converter::bytesToLengthPrefixedBinaryString)
                .reduce(ArrayConverter::concatenate)
                .orElseGet(() -> new byte[0]);
    }

    /**
     * Parses the hostkey blob into a list of hostkeys
     *
     * @param hostkeyBlob the hostkey blob
     * @return
     */
    public static List<SshPublicKey<?, ?>> parseHostkeyBlob(byte[] hostkeyBlob) {
        int offset = 0;
        List<SshPublicKey<?, ?>> hostKeyList = new ArrayList<>();
        while (offset < hostkeyBlob.length) {
            BigInteger lengthKey =
                    new BigInteger(
                            Arrays.copyOfRange(
                                    hostkeyBlob,
                                    offset,
                                    offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
            hostKeyList.add(
                    PublicKeyHelper.parse(
                            Arrays.copyOfRange(
                                    hostkeyBlob, offset, offset = offset + lengthKey.intValue())));
        }
        return hostKeyList;
    }

    public static void createHostKeySignatures(
            SshContext context, GlobalRequestHostKeysProveSuccessMessage message) {
        List<SshPublicKey<?, ?>> keysToProve =
                context.getServerHostKeys().entrySet().stream()
                        .filter(x -> Boolean.TRUE.equals(x.getValue()))
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toList());
        if (keysToProve.isEmpty()) message.setHostKeySignatures(new byte[0]);
        ByteArrayOutputStream signatureOutput = new ByteArrayOutputStream();
        for (SshPublicKey<?, ?> serverHostKey : keysToProve) {
            SigningSignature signingSignature;
            // get first match of pubkeyformat and continue with this publickeyalgorithm
            PublicKeyAlgorithm hostKeyAlgorithm =
                    Arrays.stream(PublicKeyAlgorithm.values())
                            .filter(
                                    x ->
                                            x.getKeyFormat()
                                                    .equals(serverHostKey.getPublicKeyFormat()))
                            .findFirst()
                            .get();
            try {
                signingSignature =
                        SignatureFactory.getSigningSignature(hostKeyAlgorithm, serverHostKey);
                SignatureEncoding signatureEncoding = hostKeyAlgorithm.getSignatureEncoding();
                signatureOutput.write(
                        ArrayConverter.intToBytes(
                                signatureEncoding.getName().length(),
                                DataFormatConstants.STRING_SIZE_LENGTH));
                signatureOutput.write(
                        signatureEncoding.getName().getBytes(StandardCharsets.US_ASCII));
                // string		"hostkeys-prove-00@openssh.com"
                // string		session identifier
                // string		hostkey

                byte[] content =
                        ArrayConverter.concatenate(
                                Converter.stringToLengthPrefixedBinaryString(
                                        "hostkeys-prove-00@openssh.com"),
                                Converter.bytesToLengthPrefixedBinaryString(
                                        context.getSessionID().orElse(new byte[0])),
                                Converter.bytesToLengthPrefixedBinaryString(
                                        serverHostKey.getEncoded()));
                byte[] rawSignature = signingSignature.sign(content);
                signatureOutput.write(
                        ArrayConverter.intToBytes(
                                rawSignature.length, DataFormatConstants.STRING_SIZE_LENGTH));
                signatureOutput.write(rawSignature);
                message.setHostKeySignatures(signatureOutput.toByteArray(), true);
            } catch (CryptoException e) {
                LOGGER.error(
                        "HostkeyProveMessage: An unexpected cryptographic exception occurred during signature generation, workflow will continue but signature is left blank");
                LOGGER.debug(e);
                message.setHostKeySignatures(new byte[0], true);
            } catch (IOException e) {
                LOGGER.error(
                        "HostKeyProveMessage:An unexpected IOException occured during signature generation, workflow will continue but signature is left blank");
                LOGGER.debug(e);
                message.setHostKeySignatures(new byte[0], true);
            }
        }
    }
}
