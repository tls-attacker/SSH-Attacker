/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.constants.SignatureEncoding;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;

/**
 * This class extends the JavaSignature for the DSA signature encoding by unpacking the signature
 * output / packing the input. This is necessary as BouncyCastle returns the signature as an ASN.1
 * sequence while the RFC requires both signature parts (r, s) to be "160-bit integers, without
 * lengths or padding, unsigned, and in network byte order".
 */
public class UnpackedDsaJavaSignature extends UnpackedJavaSignature {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnpackedDsaJavaSignature(PublicKeyAlgorithm algorithm, Key key) {
        super(algorithm, key);
        if (algorithm.getSignatureEncoding() != SignatureEncoding.SSH_DSS) {
            throw new IllegalArgumentException(
                    "UnpackedDsaSignature class does only support signature algorithms with ssh-dss encoding, but got "
                            + algorithm
                            + " with encoding "
                            + algorithm.getSignatureEncoding());
        }
    }

    @Override
    protected byte[] unpackSignature(byte[] packedSignature) {
        ASN1InputStream input = new ASN1InputStream(packedSignature);
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(input.readObject());
            ASN1Integer r = ASN1Integer.getInstance(sequence.getObjectAt(0));
            ASN1Integer s = ASN1Integer.getInstance(sequence.getObjectAt(1));
            // r and s are unsigned (no leading zero byte allowed), therefore use ArrayConverter
            // rather than .toByteArray() to strip the sign byte
            return ArrayConverter.concatenate(
                    ArrayConverter.bigIntegerToByteArray(r.getPositiveValue()),
                    ArrayConverter.bigIntegerToByteArray(s.getPositiveValue()));
        } catch (IOException e) {
            LOGGER.error(
                    "Caught an IOException while unpacking DSA signature from ASN.1 structure, returning an empty signature instead",
                    e);
            return new byte[0];
        }
    }

    @Override
    protected byte[] packSignature(byte[] unpackedSignature) {
        BigInteger r =
                new BigInteger(
                        1, Arrays.copyOfRange(unpackedSignature, 0, unpackedSignature.length / 2));
        BigInteger s =
                new BigInteger(
                        1,
                        Arrays.copyOfRange(
                                unpackedSignature,
                                unpackedSignature.length / 2,
                                unpackedSignature.length));
        ASN1Integer packedR = new ASN1Integer(r);
        ASN1Integer packedS = new ASN1Integer(s);
        DERSequence sequence = new DERSequence(new ASN1Encodable[] {packedR, packedS});
        try {
            ByteArrayOutputStream packedSignatureOutput = new ByteArrayOutputStream();
            ASN1OutputStream asn1Output = ASN1OutputStream.create(packedSignatureOutput);
            asn1Output.writeObject(sequence);
            return packedSignatureOutput.toByteArray();
        } catch (IOException e) {
            LOGGER.error(
                    "Caught an IOException while packing DSA signature into ASN.1 structure, returning an empty signature instead",
                    e);
            return new byte[0];
        }
    }
}
