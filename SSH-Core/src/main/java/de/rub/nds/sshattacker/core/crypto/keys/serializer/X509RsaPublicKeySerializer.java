/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.crypto.keys.CustomX509RsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.math.BigInteger;
import java.util.Date;
import java.util.Map;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * Serializer class to encode an RSA X.509 public key (X509-SSH-RSA) format for SSH Exchange Hash
 * Input.
 */
public class X509RsaPublicKeySerializer extends Serializer<CustomX509RsaPublicKey> {

    @Override
    protected void serializeBytes(CustomX509RsaPublicKey object, SerializerStream output) {
        try {
            // Step 1: Add additional bytes at the beginning
            byte[] prefix = {0x30, (byte) 0x82}; // Example: exact bytes from server
            output.appendBytes(prefix);

            // Step 2: Create the ASN.1 vector for the entire certificate
            ASN1EncodableVector topLevelVector = new ASN1EncodableVector();
            // 1. Version (uint32)
            appendInt(
                    topLevelVector,
                    2,
                    1); // X.509 Version 3 is represented as 2 in ASN.1 and it's a single byte

            // 2. Serial Number (mpint)
            appendBigInteger(
                    topLevelVector,
                    BigInteger.valueOf(object.getSerial()),
                    20); // Updated to use correct serial number size

            // 3. Signature Algorithm
            AlgorithmIdentifier signatureAlgorithm =
                    new AlgorithmIdentifier(
                            new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"),
                            DERNull.INSTANCE); // OID for sha256WithRSAEncryption
            topLevelVector.add(signatureAlgorithm);

            // 4. Issuer (Distinguished Name)
            ASN1Sequence issuerSequence =
                    PublicKeySerializerHelper.getDistinguishedNameAsASN1(object.getIssuer(), true);
            topLevelVector.add(issuerSequence);

            // 5. Validity Period (ASN.1 GeneralizedTime)
            ASN1Sequence validitySequence =
                    getValidityPeriodAsASN1(object.getValidAfter(), object.getValidBefore());
            topLevelVector.add(validitySequence);

            // 6. Subject (Distinguished Name)
            ASN1Sequence subjectSequence =
                    PublicKeySerializerHelper.getDistinguishedNameAsASN1(object.getSubject(), true);
            topLevelVector.add(subjectSequence);

            // 7. Public Key Algorithm (OID)
            AlgorithmIdentifier publicKeyAlgorithm =
                    new AlgorithmIdentifier(
                            new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"),
                            DERNull.INSTANCE); // OID for rsaEncryption
            topLevelVector.add(publicKeyAlgorithm);

            // 8. Public Key (Modulus and Exponent as ASN.1 SEQUENCE)
            ASN1EncodableVector publicKeyVector = new ASN1EncodableVector();
            publicKeyVector.add(new ASN1Integer(object.getModulus()));
            publicKeyVector.add(new ASN1Integer(object.getPublicExponent()));
            ASN1Sequence publicKeySequence = new DERSequence(publicKeyVector);
            topLevelVector.add(publicKeySequence);

            // 9. Extensions (ASN.1 encoded as Extensions sequence)
            Extensions extensions = getExtensionsAsASN1(object.getExtensions());
            if (extensions != null) {
                topLevelVector.add(extensions);
            }

            // Step 3: Signature Algorithm Information
            AlgorithmIdentifier signatureAlgId =
                    new AlgorithmIdentifier(
                            new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"),
                            DERNull.INSTANCE); // sha256WithRSAEncryption
            topLevelVector.add(signatureAlgId);

            // Step 4: Signature Value (ASN.1 Bit String)
            byte[] signature = object.getSignature();
            if (signature == null) {
                throw new IllegalStateException("Signature is not set in the publicKey");
            }
            topLevelVector.add(new DERBitString(signature));

            // Step 5: Serialize the entire ASN.1 block
            ASN1Sequence topLevelSequence = new DERSequence(topLevelVector);
            byte[] asn1Encoded = topLevelSequence.getEncoded();
            output.appendBytes(asn1Encoded);

        } catch (Exception e) {
            throw new RuntimeException("Error serializing X509 RSA Public Key", e);
        }
    }

    /** Helper method to serialize the validity period in ASN.1 format. */
    private static ASN1Sequence getValidityPeriodAsASN1(long validAfter, long validBefore) {
        try {
            ASN1GeneralizedTime notBefore = new ASN1GeneralizedTime(new Date(validAfter));
            ASN1GeneralizedTime notAfter = new ASN1GeneralizedTime(new Date(validBefore));

            ASN1EncodableVector validityVector = new ASN1EncodableVector();
            validityVector.add(notBefore);
            validityVector.add(notAfter);

            return new DERSequence(validityVector);
        } catch (Exception e) {
            throw new RuntimeException("Error encoding Validity Period", e);
        }
    }

    /** Helper method to serialize Extensions in ASN.1 format. */
    private static Extensions getExtensionsAsASN1(Map<String, String> extensionsMap) {
        if (extensionsMap != null && !extensionsMap.isEmpty()) {
            try {
                ASN1EncodableVector extensionsVector = new ASN1EncodableVector();
                for (Map.Entry<String, String> entry : extensionsMap.entrySet()) {
                    ASN1ObjectIdentifier oid;
                    DEROctetString value;

                    switch (entry.getKey()) {
                        case "SubjectKeyIdentifier":
                            oid = Extension.subjectKeyIdentifier;
                            value =
                                    new DEROctetString(
                                            PublicKeySerializerHelper.parseExtensionValue(
                                                    entry.getValue()));
                            break;
                        case "AuthorityKeyIdentifier":
                            oid = Extension.authorityKeyIdentifier;
                            value =
                                    new DEROctetString(
                                            PublicKeySerializerHelper.parseExtensionValue(
                                                    entry.getValue()));
                            break;
                        case "KeyUsage":
                            oid = Extension.keyUsage;
                            value =
                                    new DEROctetString(
                                            PublicKeySerializerHelper.parseExtensionValue(
                                                    entry.getValue()));
                            break;
                        case "ExtendedKeyUsage":
                            oid = Extension.extendedKeyUsage;
                            value =
                                    new DEROctetString(
                                            PublicKeySerializerHelper.parseExtensionValue(
                                                    entry.getValue()));
                            break;
                        case "BasicConstraints":
                            oid = Extension.basicConstraints;
                            value =
                                    new DEROctetString(
                                            PublicKeySerializerHelper.parseExtensionValue(
                                                    entry.getValue()));
                            break;
                        default:
                            throw new IllegalArgumentException(
                                    "Unsupported extension key: " + entry.getKey());
                    }

                    Extension extension = new Extension(oid, false, value);
                    extensionsVector.add(extension);
                }
                return Extensions.getInstance(new DERSequence(extensionsVector));
            } catch (Exception e) {
                throw new RuntimeException("Error encoding Extensions", e);
            }
        }
        return null;
    }

    /** Helper method to serialize a BigInteger (mpint) in SSH format. */
    private static void appendBigInteger(ASN1EncodableVector vector, BigInteger value, int length) {
        if (value.bitLength() > length * 8) {
            throw new IllegalArgumentException("mpint too large");
        }
        byte[] mpintBytes = value.toByteArray();
        vector.add(new DEROctetString(mpintBytes));
    }

    /** Helper method to serialize integer values. */
    private static void appendInt(ASN1EncodableVector vector, int value, int length) {
        byte[] intBytes = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            intBytes[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        vector.add(new DEROctetString(intBytes));
    }
}
