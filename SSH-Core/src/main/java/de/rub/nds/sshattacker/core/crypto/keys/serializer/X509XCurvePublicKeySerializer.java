/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.crypto.keys.CustomX509XCurvePublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

/** Serializer class to encode an ED25519 X.509 public key (X509-SSH-ED25519) format. */
public class X509XCurvePublicKeySerializer extends Serializer<CustomX509XCurvePublicKey> {

    @Override
    protected void serializeBytes(CustomX509XCurvePublicKey object, SerializerStream output) {
        try {
            ASN1EncodableVector topLevelVector = new ASN1EncodableVector();

            // Version (uint32) as ASN.1 INTEGER
            topLevelVector.add(new ASN1Integer(object.getVersion()));

            // Serial (uint64) as ASN.1 INTEGER
            topLevelVector.add(new ASN1Integer(BigInteger.valueOf(object.getSerial())));

            // Signature Algorithm (ED25519 as OID in ASN.1 format with NULL parameter)
            AlgorithmIdentifier signatureAlgorithm =
                    new AlgorithmIdentifier(
                            new ASN1ObjectIdentifier("1.3.101.112"),
                            DERNull.INSTANCE); // OID for Ed25519
            topLevelVector.add(signatureAlgorithm);

            // Issuer (Distinguished Name in ASN.1 format)
            ASN1Sequence issuerSequence =
                    PublicKeySerializerHelper.getDistinguishedNameAsASN1(object.getIssuer(), false);
            topLevelVector.add(issuerSequence);

            // Validity Period (ASN.1 GeneralizedTime for Not Before and Not After)
            ASN1Sequence validitySequence =
                    PublicKeySerializerHelper.getValidityPeriodAsASN1(
                            object.getValidAfter(), object.getValidBefore());
            topLevelVector.add(validitySequence);

            // Subject (Distinguished Name in ASN.1 format)
            ASN1Sequence subjectSequence =
                    PublicKeySerializerHelper.getDistinguishedNameAsASN1(
                            object.getSubject(), false);
            topLevelVector.add(subjectSequence);

            // Public Key Algorithm (OID for ED25519 with NULL parameter)
            AlgorithmIdentifier publicKeyAlgorithm =
                    new AlgorithmIdentifier(
                            new ASN1ObjectIdentifier("1.3.101.112"),
                            DERNull.INSTANCE); // OID for Ed25519
            topLevelVector.add(publicKeyAlgorithm);

            // Public Key (as ASN.1 OCTET STRING)
            topLevelVector.add(new DEROctetString(object.getPublicKey()));

            // Extensions (ASN.1 encoded as Extensions sequence)
            Extensions extensions = getExtensionsAsASN1(object.getExtensions());
            if (extensions != null) {
                topLevelVector.add(extensions);
            }

            // Signature (string) as ASN.1 OctetString
            byte[] signature = object.getSignature();
            if (signature == null) {
                throw new IllegalStateException("Signature is not set in the publicKey");
            }
            topLevelVector.add(new DEROctetString(signature));

            // Serialize the entire ASN.1 structure
            ASN1Sequence topLevelSequence = new DERSequence(topLevelVector);
            byte[] asn1Encoded = topLevelSequence.getEncoded();
            output.appendBytes(asn1Encoded);

        } catch (Exception e) {
            throw new RuntimeException("Error serializing X509 ED25519 Public Key", e);
        }
    }

    /** Utility method to serialize extensions as ASN.1 Extensions. */
    private static Extensions getExtensionsAsASN1(Map<String, String> extensionsMap) {
        if (extensionsMap != null && !extensionsMap.isEmpty()) {
            try {
                ASN1EncodableVector extensionsVector = new ASN1EncodableVector();
                for (Map.Entry<String, String> entry : extensionsMap.entrySet()) {
                    String oidString = entry.getKey();

                    // OID for known extensions
                    if (oidString.equals("SubjectKeyIdentifier")) {
                        oidString = "2.5.29.14";
                    }
                    if (oidString.equals("AuthorityKeyIdentifier")) {
                        oidString = "2.5.29.35";
                    }

                    // Test if valid OID
                    if (!oidString.matches("^\\d+(\\.\\d+)*$")) {
                        throw new IllegalArgumentException("Invalid OID format: " + oidString);
                    }

                    ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidString);
                    DEROctetString value =
                            new DEROctetString(entry.getValue().getBytes(StandardCharsets.UTF_8));
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
}
