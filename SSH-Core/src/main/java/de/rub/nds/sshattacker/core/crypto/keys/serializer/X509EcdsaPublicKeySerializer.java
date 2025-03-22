/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.crypto.keys.CustomX509EcdsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.math.BigInteger;
import java.util.Map;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

/** Serializer class to encode an ECDSA X.509 public key (X509-SSH-ECDSA) format. */
public class X509EcdsaPublicKeySerializer extends Serializer<CustomX509EcdsaPublicKey> {

    @Override
    protected void serializeBytes(CustomX509EcdsaPublicKey object, SerializerStream output) {
        /*
         * The X509-SSH-ECDSA format as specified:
         *   uint32    version
         *   uint64    serial
         *   string    signature algorithm
         *   string    issuer (Distinguished Name - DN)
         *   uint64    valid after
         *   uint64    valid before
         *   string    subject (Distinguished Name - DN)
         *   string    public key algorithm
         *   string    curve name
         *   string    public key (ECPoint)
         *   string    extensions
         *   string    signature
         */

        try {
            ASN1EncodableVector topLevelVector = new ASN1EncodableVector();

            // Version (uint32) as ASN.1 INTEGER
            topLevelVector.add(new ASN1Integer(object.getVersion()));

            // Serial (uint64) as ASN.1 INTEGER
            topLevelVector.add(new ASN1Integer(BigInteger.valueOf(object.getSerial())));

            // Signature Algorithm (OID for ECDSA with SHA256)
            AlgorithmIdentifier signatureAlgorithm =
                    new AlgorithmIdentifier(
                            new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"),
                            DERNull.INSTANCE); // OID for ecdsa-with-SHA256
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

            // Public Key Algorithm (OID for ECDSA)
            AlgorithmIdentifier publicKeyAlgorithm =
                    new AlgorithmIdentifier(
                            new ASN1ObjectIdentifier("1.2.840.10045.2.1"),
                            DERNull.INSTANCE); // OID for id-ecPublicKey
            topLevelVector.add(publicKeyAlgorithm);

            // Curve Name (as ASN.1 Object Identifier for the specific curve, e.g., NIST P-256)
            ASN1ObjectIdentifier curveOid = new ASN1ObjectIdentifier(object.getGroup().getOid());
            topLevelVector.add(curveOid);

            // Public Key (as ASN.1 SEQUENCE for ECPoint)
            ASN1EncodableVector publicKeyVector = new ASN1EncodableVector();
            publicKeyVector.add(new ASN1Integer(object.getW().getAffineX()));
            publicKeyVector.add(new ASN1Integer(object.getW().getAffineY()));
            ASN1Sequence publicKeySequence = new DERSequence(publicKeyVector);
            topLevelVector.add(new DERBitString(publicKeySequence));

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
            throw new RuntimeException("Error serializing X509 ECDSA Public Key", e);
        }
    }

    /** Utility method to serialize extensions as ASN.1 Extensions. */
    private static Extensions getExtensionsAsASN1(Map<String, String> extensionsMap) {
        if (extensionsMap != null && !extensionsMap.isEmpty()) {
            try {
                ASN1EncodableVector extensionsVector = new ASN1EncodableVector();
                for (Map.Entry<String, String> entry : extensionsMap.entrySet()) {
                    String key = entry.getKey();
                    ASN1ObjectIdentifier oid;
                    DEROctetString value =
                            switch (key) {
                                case "SubjectKeyIdentifier" -> {
                                    oid = Extension.subjectKeyIdentifier;
                                    yield new DEROctetString(
                                            PublicKeySerializerHelper.parseExtensionValue(
                                                    entry.getValue()));
                                }
                                case "AuthorityKeyIdentifier" -> {
                                    oid = Extension.authorityKeyIdentifier;
                                    yield new DEROctetString(
                                            PublicKeySerializerHelper.parseExtensionValue(
                                                    entry.getValue()));
                                }
                                default ->
                                        throw new IllegalArgumentException(
                                                "Unsupported extension key: " + key);
                            };

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
