/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.util;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.*;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class KeyParser {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeyParser() {}

    /**
     * Reads a private key from a file and returns it as an SshPublicKey, only containing the public
     * component of the key
     *
     * @param path path to the file containing the public key
     * @return
     */
    public static SshPublicKey<?, ?> readPublicKeyFromBytes(String path) {
        InputStream inputStream = KeyParser.class.getClassLoader().getResourceAsStream(path);
        byte[] publicKeyBytes;
        try {
            publicKeyBytes = inputStream.readAllBytes();
            if (publicKeyBytes == null) {
                LOGGER.error(
                        "Error occured reading user key:"
                                + path
                                + ", continue without adding key!");
                return null;
            }
        } catch (IOException e) {
            LOGGER.error(
                    "Error occured reading user key:" + path + ", continue without adding key!");
            return null;
        }
        int offset = 0;
        byte[] keyBytes = unwrapPublicKeyBytes(publicKeyBytes);
        return PublicKeyHelper.parse(Arrays.copyOfRange(keyBytes, offset, keyBytes.length));
    }

    /**
     * Reads a private key from a file and returns it as an SshPrivateKey, containing both key
     * components
     *
     * @param path path to the file containing the private key
     * @return
     */
    public static SshPublicKey<?, ?> readKeyPairFromBytes(String path) {
        InputStream inputStream = KeyParser.class.getClassLoader().getResourceAsStream(path);
        byte[] privateKeyBytes;
        try {
            privateKeyBytes = inputStream.readAllBytes();
            if (privateKeyBytes == null) {
                LOGGER.error(
                        "Error occured reading user key:"
                                + path
                                + ", continue without adding key!");
                return null;
            }
        } catch (IOException e) {
            LOGGER.error(
                    "Error occured reading user key: " + path + ", continue without adding key!");
            return null;
        }
        byte[] keyBytes;
        try {
            keyBytes = unwrapPrivateKeyBytes(privateKeyBytes);
        } catch (IllegalArgumentException e) {
            LOGGER.error(
                    "Wrong key format provided: "
                            + path
                            + "please check to provide ssh private key to readKeyPairFromFile()");
            return null;
        }
        if (keyBytes.length == 0) {
            LOGGER.error("Provided keyfiles was empty, please recheck " + path);
            return null;
        }
        int offset = 0;
        String fixedString = new String(Arrays.copyOfRange(keyBytes, offset, offset = offset + 14));
        // if the keybytes are starting with this string, we have to deal with a open-ssh key file,
        // containing private and public key specs
        if (!fixedString.equals("openssh-key-v1")) {
            LOGGER.error(
                    "Currently only support for open-ssh keys is supported, failed to read key from "
                            + path);
            return null;
        }
        // in this case we need to add +1 on the parser, because the string is finished with a
        // null-byte, but would be interpreted wrong by Java
        offset = offset + 1;
        BigInteger lengthCipherName =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        String ciphername =
                new String(
                        Arrays.copyOfRange(
                                keyBytes, offset, offset = offset + lengthCipherName.intValue()));
        BigInteger lengthKdfName =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        String kdfname =
                new String(
                        Arrays.copyOfRange(
                                keyBytes, offset, offset = offset + lengthKdfName.intValue()));

        BigInteger lengthKdf =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        if (lengthKdf.intValue() != 0) { // ToDo
        }
        BigInteger numberOfKeys =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        BigInteger pubkeyLength =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));

        SshPublicKey sshPublicKey =
                PublicKeyHelper.parse(
                        Arrays.copyOfRange(
                                keyBytes, offset, offset = offset + pubkeyLength.intValue()));
        BigInteger privKeyLength =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes, offset, offset + DataFormatConstants.MPINT_SIZE_LENGTH));

        sshPublicKey.setPrivateKey(
                parsePrivateKey(
                        Arrays.copyOfRange(keyBytes, offset, offset + privKeyLength.intValue())));
        return sshPublicKey;
    }

    /**
     * Parses a private key, first analysing which pubkey type needs to be parsed
     *
     * @param keyBytes the key bytes to parse
     * @return a CustomPrivateKey containing the parsed key
     */
    public static CustomPrivateKey parsePrivateKey(byte[] keyBytes) {
        int offset = 0;
        offset = offset + 12;
        BigInteger lengthPubKeyAlg =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        String pubKeyAlg =
                new String(
                        Arrays.copyOfRange(
                                keyBytes, offset, offset = offset + lengthPubKeyAlg.intValue()));

        // 32-bit length for rnd+prv+comment+pad
        //    64-bit dummy checksum?  # a random 32-bit int, repeated
        //    32-bit length, keytype  # the private key (including public)
        //    32-bit length, pub0     # Public Key parts
        //    32-bit length, pub1
        //    32-bit length, prv0     # Private Key parts
        //    ...                     # (number varies by type)
        //    32-bit length, comment  # comment string
        //    padding bytes 0x010203
        switch (pubKeyAlg) {
            case "ssh-rsa":
                return readRsaPrivateKey(Arrays.copyOfRange(keyBytes, offset, keyBytes.length));
            case "ecdsa-sha2-nistp256":
            case "ecdsa-sha2-nistp384":
            case "ecdsa-sha2-nistp521":
                return readEcdsaPrivateKey(Arrays.copyOfRange(keyBytes, offset, keyBytes.length));
            case "ssh-ed25519":
                return readEd25519PrivateKey(Arrays.copyOfRange(keyBytes, offset, keyBytes.length));
            case "ssh-dss":
                return readDsaPrivateKey(Arrays.copyOfRange(keyBytes, offset, keyBytes.length));
            default:
                LOGGER.error("");
                return null;
        }
    }

    /**
     * Reads a RSA private key from the given key bytes
     *
     * @param keyBytes the key bytes to read
     * @return a CustomRsaPrivateKey containing the parsed key
     */
    public static CustomRsaPrivateKey readRsaPrivateKey(byte[] keyBytes) {
        int offset = 0;
        BigInteger lengthN =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        BigInteger n =
                new BigInteger(
                        Arrays.copyOfRange(keyBytes, offset, offset = offset + lengthN.intValue()));
        BigInteger lengthE =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        offset = offset + lengthE.intValue(); // because the coordinates have already been read from
        // the pubkey, this step can be skipped right here
        BigInteger lengthD =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        BigInteger d =
                new BigInteger(
                        Arrays.copyOfRange(keyBytes, offset, offset = offset + lengthD.intValue()));
        // we don't need to read any further for now, but performance-wise it might be needed
        // someday
        return new CustomRsaPrivateKey(d, n);
    }

    /**
     * Reads a ECDSA private key from the given key bytes
     *
     * @param keyBytes the key bytes to read
     * @return a CustomEcPrivateKey containing the parsed key
     */
    public static CustomEcPrivateKey readEcdsaPrivateKey(byte[] keyBytes) {
        int offset = 0;
        BigInteger curveSpeclength =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        String curveSpec =
                new String(
                        Arrays.copyOfRange(
                                keyBytes, offset, offset = offset + curveSpeclength.intValue()));
        BigInteger lengthCoordinates =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        offset =
                offset
                        + lengthCoordinates
                                .intValue(); // because the coordinates have already been read from
        // the pubkey, this step can be skipped right here
        BigInteger lengthScalar =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        BigInteger privateKey =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes, offset, offset = offset + lengthScalar.intValue()));
        return new CustomEcPrivateKey(privateKey, NamedEcGroup.fromIdentifier(curveSpec));
    }

    /**
     * Reads a Ed25519 private key from the given key bytes
     *
     * @param keyBytes the key bytes to read
     * @return a XCurveEcPrivateKey containing the parsed key
     */
    public static XCurveEcPrivateKey readEd25519PrivateKey(byte[] keyBytes) {
        int offset = 0;
        BigInteger lengthCoordinate =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        offset =
                offset
                        + lengthCoordinate
                                .intValue(); // because the coordinates have already been read from
        // the pubkey, this step can be skipped right here
        BigInteger lengthScalar =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        byte[] scalar =
                Arrays.copyOfRange(keyBytes, offset, offset = offset + lengthScalar.intValue() / 2);
        return new XCurveEcPrivateKey(scalar, NamedEcGroup.CURVE25519);
    }

    /**
     * Reads a DSA private key from the given key bytes
     *
     * @param keyBytes the key bytes to read
     * @return a CustomDsaPrivateKey containing the parsed key
     */
    public static CustomDsaPrivateKey readDsaPrivateKey(byte[] keyBytes) {
        int offset = 0;
        BigInteger lengthP =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        BigInteger p =
                new BigInteger(
                        Arrays.copyOfRange(keyBytes, offset, offset = offset + lengthP.intValue()));
        BigInteger lengthQ =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        BigInteger q =
                new BigInteger(
                        Arrays.copyOfRange(keyBytes, offset, offset = offset + lengthQ.intValue()));
        BigInteger lengthG =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        BigInteger g =
                new BigInteger(
                        Arrays.copyOfRange(keyBytes, offset, offset = offset + lengthG.intValue()));
        BigInteger lengthY =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        offset = offset + lengthY.intValue();
        BigInteger lengthX =
                new BigInteger(
                        Arrays.copyOfRange(
                                keyBytes,
                                offset,
                                offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
        BigInteger x =
                new BigInteger(
                        Arrays.copyOfRange(keyBytes, offset, offset = offset + lengthX.intValue()));
        return new CustomDsaPrivateKey(p, q, g, x);
    }

    /**
     * Unwraps the public key bytes from the public key file
     *
     * @param publicKeyBytes the public key bytes
     * @return
     */
    public static byte[] unwrapPublicKeyBytes(byte[] publicKeyBytes) {
        // pubkey structure ssh-rsa AAAAB3NzaC1yc2E...Q02P1Eamz/nT4I3 root@localhost thus we want to
        // cut the last part of the pubkey holding the ownership
        String unwrappedKey = new String(publicKeyBytes, Charset.defaultCharset()).split(" ")[1];
        // replacements for public keyfile
        for (PublicKeyFormat keyformat : PublicKeyFormat.values()) {
            // we can replace the key type right here because it is kept in the key data anyways
            unwrappedKey = unwrappedKey.replace(keyformat.getName(), "");
        }
        // == are not accepted as Base64 Java encoding so we need to cut them off too
        unwrappedKey =
                unwrappedKey
                        .replace(" ", "")
                        .replace("=", "")
                        .replaceAll(System.lineSeparator(), "");
        return Base64.getDecoder().decode(unwrappedKey);
    }

    /**
     * Unwraps the private key bytes from the keyfile
     *
     * @param privateKeyBytes the private key bytes
     * @return
     */
    private static byte[] unwrapPrivateKeyBytes(byte[] privateKeyBytes) {
        // replacements for private key
        // == are not accepted as Base64 Java encoding so we need to cut them off too
        String unwrappedKey =
                new String(privateKeyBytes, Charset.defaultCharset())
                        .replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END OPENSSH PRIVATE KEY-----", "")
                        .replace("-----END RSA PRIVATE KEY-----", "")
                        .replace("=", "");
        byte[] keyBytes = Base64.getDecoder().decode(unwrappedKey);
        return keyBytes;
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
}
