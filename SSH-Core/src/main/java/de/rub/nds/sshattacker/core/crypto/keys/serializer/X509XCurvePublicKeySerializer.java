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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

/** Serializer class to encode an ED25519 X.509 public key (X509-SSH-ED25519) format. */
public class X509XCurvePublicKeySerializer extends Serializer<CustomX509XCurvePublicKey> {

    private final CustomX509XCurvePublicKey publicKey;

    public X509XCurvePublicKeySerializer(CustomX509XCurvePublicKey publicKey) {
        super();
        this.publicKey = publicKey;
    }

    @Override
    protected void serializeBytes() {
        try {
            ASN1EncodableVector topLevelVector = new ASN1EncodableVector();

            // Version (uint32) as ASN.1 INTEGER
            topLevelVector.add(new ASN1Integer(publicKey.getVersion()));

            // Serial (uint64) as ASN.1 INTEGER
            topLevelVector.add(new ASN1Integer(BigInteger.valueOf(publicKey.getSerial())));

            // Signature Algorithm (ED25519 as OID in ASN.1 format with NULL parameter)
            AlgorithmIdentifier signatureAlgorithm =
                    new AlgorithmIdentifier(
                            new ASN1ObjectIdentifier("1.3.101.112"),
                            DERNull.INSTANCE); // OID for Ed25519
            topLevelVector.add(signatureAlgorithm);

            // Issuer (Distinguished Name in ASN.1 format)
            ASN1Sequence issuerSequence = getDistinguishedNameAsASN1(publicKey.getIssuer());
            topLevelVector.add(issuerSequence);

            // Validity Period (ASN.1 GeneralizedTime for Not Before and Not After)
            ASN1Sequence validitySequence =
                    getValidityPeriodAsASN1(publicKey.getValidAfter(), publicKey.getValidBefore());
            topLevelVector.add(validitySequence);

            // Subject (Distinguished Name in ASN.1 format)
            ASN1Sequence subjectSequence = getDistinguishedNameAsASN1(publicKey.getSubject());
            topLevelVector.add(subjectSequence);

            // Public Key Algorithm (OID for ED25519 with NULL parameter)
            AlgorithmIdentifier publicKeyAlgorithm =
                    new AlgorithmIdentifier(
                            new ASN1ObjectIdentifier("1.3.101.112"),
                            DERNull.INSTANCE); // OID for Ed25519
            topLevelVector.add(publicKeyAlgorithm);

            // Public Key (as ASN.1 OCTET STRING)
            topLevelVector.add(new DEROctetString(publicKey.getPublicKey()));

            // Extensions (ASN.1 encoded as Extensions sequence)
            Extensions extensions = getExtensionsAsASN1(publicKey.getExtensions());
            if (extensions != null) {
                topLevelVector.add(extensions);
            }

            // Signature (string) as ASN.1 OctetString
            byte[] signature = publicKey.getSignature();
            if (signature == null) {
                throw new IllegalStateException("Signature is not set in the publicKey");
            }
            topLevelVector.add(new DEROctetString(signature));

            // Serialize the entire ASN.1 structure
            ASN1Sequence topLevelSequence = new DERSequence(topLevelVector);
            byte[] asn1Encoded = topLevelSequence.getEncoded();
            appendBytes(asn1Encoded);

        } catch (Exception e) {
            throw new RuntimeException("Error serializing X509 ED25519 Public Key", e);
        }
    }

    /** Utility method to serialize Distinguished Names (DN) in ASN.1 format using BouncyCastle. */
    private ASN1Sequence getDistinguishedNameAsASN1(String dn) {
        if (dn != null && !dn.isEmpty()) {
            try {
                X500Name x500Name = new X500Name(dn);
                return (ASN1Sequence)
                        x500Name.toASN1Primitive(); // Correct typecasting to ASN1Sequence
            } catch (Exception e) {
                throw new RuntimeException("Error encoding Distinguished Name", e);
            }
        } else {
            throw new IllegalArgumentException("Distinguished Name cannot be null or empty");
        }
    }

    /** Utility method to serialize validity period as ASN.1 GeneralizedTime. */
    private ASN1Sequence getValidityPeriodAsASN1(long validAfter, long validBefore) {
        try {
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            String validAfterStr = dateFormat.format(new Date(validAfter * 1000));
            String validBeforeStr = dateFormat.format(new Date(validBefore * 1000));

            ASN1EncodableVector validityVector = new ASN1EncodableVector();
            validityVector.add(new ASN1GeneralizedTime(validAfterStr));
            validityVector.add(new ASN1GeneralizedTime(validBeforeStr));

            return new DERSequence(validityVector);
        } catch (Exception e) {
            throw new RuntimeException("Error encoding Validity Period", e);
        }
    }

    /** Utility method to serialize extensions as ASN.1 Extensions. */
    private Extensions getExtensionsAsASN1(Map<String, String> extensionsMap) {
        if (extensionsMap != null && !extensionsMap.isEmpty()) {
            try {
                ASN1EncodableVector extensionsVector = new ASN1EncodableVector();
                for (Map.Entry<String, String> entry : extensionsMap.entrySet()) {
                    String oidString = entry.getKey();

                    // OID for known extensions
                    if (oidString.equals("SubjectKeyIdentifier")) {
                        oidString = "2.5.29.14";
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
