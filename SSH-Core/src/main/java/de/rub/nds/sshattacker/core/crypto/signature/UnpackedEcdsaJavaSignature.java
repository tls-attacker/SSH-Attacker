/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.util.Converter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;

/**
 * This class extends the JavaSignature for the ECDSA signature encoding by unpacking the signature
 * output / packing the input. This is necessary as BouncyCastle returns the signature as an ASN.1
 * sequence while the RFC requires both signature parts (r, s) to be encoded as mpint.
 */
public class UnpackedEcdsaJavaSignature extends UnpackedJavaSignature {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnpackedEcdsaJavaSignature(PublicKeyAlgorithm algorithm, Key key) {
        super(algorithm, key);
        if (!algorithm.getSignatureEncoding().getName().startsWith("ecdsa-sha2-")) {
            throw new IllegalArgumentException(
                    "UnpackedEcdsaSignature class does only support signature algorithms with ecdsa-sha2-* encoding, but got "
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
            return ArrayConverter.concatenate(
                    Converter.bigIntegerToMpint(r.getPositiveValue()),
                    Converter.bigIntegerToMpint(s.getPositiveValue()));
        } catch (IOException e) {
            LOGGER.error(
                    "Caught an IOException while unpacking ECDSA signature from ASN.1 structure, returning an empty signature instead",
                    e);
            return new byte[0];
        }
    }

    @Override
    protected byte[] packSignature(byte[] unpackedSignature) {
        int rStart = DataFormatConstants.MPINT_SIZE_LENGTH;
        int rLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(unpackedSignature, 0, rStart));
        int rEnd = rStart + rLength;
        BigInteger r = new BigInteger(Arrays.copyOfRange(unpackedSignature, rStart, rEnd));
        int sStart = rEnd + DataFormatConstants.MPINT_SIZE_LENGTH;
        int sLength =
                ArrayConverter.bytesToInt(Arrays.copyOfRange(unpackedSignature, rEnd, sStart));
        int sEnd = sStart + sLength;
        BigInteger s = new BigInteger(Arrays.copyOfRange(unpackedSignature, sStart, sEnd));
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
                    "Caught an IOException while packing ECDSA signature into ASN.1 structure, returning an empty signature instead",
                    e);
            return new byte[0];
        }
    }
}
