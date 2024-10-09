package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.crypto.keys.CustomX509RsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;

import java.math.BigInteger;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.Arrays;

/**
 * Serializer class to encode an RSA X.509 public key (X509-SSH-RSA) format for SSH Exchange Hash Input.
 */
public class X509RsaPublicKeySerializer extends Serializer<CustomX509RsaPublicKey> {

    private final CustomX509RsaPublicKey publicKey;

    public X509RsaPublicKeySerializer(CustomX509RsaPublicKey publicKey) {
        super();
        this.publicKey = publicKey;
    }

    @Override
    protected void serializeBytes() {
        try {
            // Step 1: Add additional bytes at the beginning
            byte[] prefix = new byte[] { 0x30, (byte) 0x82}; // Example: exact bytes from server
            appendBytes(prefix);

            // Step 2: Create the ASN.1 vector for the entire certificate
            ASN1EncodableVector topLevelVector = new ASN1EncodableVector();

            // 1. Version (uint32)
            appendInt(topLevelVector, 2, 1); // X.509 Version 3 is represented as 2 in ASN.1 and it's a single byte

            // 2. Serial Number (mpint)
            appendBigInteger(topLevelVector, BigInteger.valueOf(publicKey.getSerial()), 20); // Updated to use correct serial number size

            // 3. Signature Algorithm
            AlgorithmIdentifier signatureAlgorithm = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"), DERNull.INSTANCE); // OID for sha256WithRSAEncryption
            topLevelVector.add(signatureAlgorithm);

            // 4. Issuer (Distinguished Name)
            ASN1Sequence issuerSequence = getDistinguishedNameAsASN1(publicKey.getIssuer());
            topLevelVector.add(issuerSequence);

            // 5. Validity Period (ASN.1 GeneralizedTime)
            ASN1Sequence validitySequence = getValidityPeriodAsASN1(publicKey.getValidAfter(), publicKey.getValidBefore());
            topLevelVector.add(validitySequence);

            // 6. Subject (Distinguished Name)
            ASN1Sequence subjectSequence = getDistinguishedNameAsASN1(publicKey.getSubject());
            topLevelVector.add(subjectSequence);

            // 7. Public Key Algorithm (OID)
            AlgorithmIdentifier publicKeyAlgorithm = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"), DERNull.INSTANCE); // OID for rsaEncryption
            topLevelVector.add(publicKeyAlgorithm);

            // 8. Public Key (Modulus and Exponent as ASN.1 SEQUENCE)
            ASN1EncodableVector publicKeyVector = new ASN1EncodableVector();
            publicKeyVector.add(new ASN1Integer(publicKey.getModulus()));
            publicKeyVector.add(new ASN1Integer(publicKey.getPublicExponent()));
            ASN1Sequence publicKeySequence = new DERSequence(publicKeyVector);
            topLevelVector.add(publicKeySequence);

            // 9. Extensions (ASN.1 encoded as Extensions sequence)
            Extensions extensions = getExtensionsAsASN1(publicKey.getExtensions());
            if (extensions != null) {
                topLevelVector.add(extensions);
            }

            // Step 3: Signature Algorithm Information
            AlgorithmIdentifier signatureAlgId = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"), DERNull.INSTANCE); // sha256WithRSAEncryption
            topLevelVector.add(signatureAlgId);

            // Step 4: Signature Value (ASN.1 Bit String)
            byte[] signature = publicKey.getSignature();
            if (signature == null) {
                throw new IllegalStateException("Signature is not set in the publicKey");
            }
            topLevelVector.add(new DERBitString(signature));

            // Step 5: Serialize the entire ASN.1 block
            ASN1Sequence topLevelSequence = new DERSequence(topLevelVector);
            byte[] asn1Encoded = topLevelSequence.getEncoded();
            appendBytes(asn1Encoded);

        } catch (Exception e) {
            throw new RuntimeException("Error serializing X509 RSA Public Key", e);
        }
    }

    /**
     * Helper method to serialize Distinguished Names (DN) in ASN.1 format.
     */
    private ASN1Sequence getDistinguishedNameAsASN1(String dn) {
        if (dn == null || dn.trim().isEmpty()) {
            throw new IllegalArgumentException("Distinguished Name cannot be null or empty");
        }
        try {
            X500Name x500Name = new X500Name(reverseDistinguishedName(dn));
            return (ASN1Sequence) x500Name.toASN1Primitive();
        } catch (Exception e) {
            throw new RuntimeException("Error encoding Distinguished Name", e);
        }
    }

    /**
     * Helper method to reverse the order of Distinguished Name components.
     */
    private String reverseDistinguishedName(String dn) {
        return Arrays.stream(dn.split(","))
                .map(String::trim)
                .collect(Collectors.collectingAndThen(Collectors.toList(), lst -> {
                    java.util.Collections.reverse(lst);
                    return String.join(", ", lst);
                }));
    }

    /**
     * Helper method to serialize the validity period in ASN.1 format.
     */
    private ASN1Sequence getValidityPeriodAsASN1(long validAfter, long validBefore) {
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

    /**
     * Helper method to serialize Extensions in ASN.1 format.
     */
    private Extensions getExtensionsAsASN1(Map<String, String> extensionsMap) {
        if (extensionsMap != null && !extensionsMap.isEmpty()) {
            try {
                ASN1EncodableVector extensionsVector = new ASN1EncodableVector();
                for (Map.Entry<String, String> entry : extensionsMap.entrySet()) {
                    ASN1ObjectIdentifier oid;
                    DEROctetString value;

                    switch (entry.getKey()) {
                        case "SubjectKeyIdentifier":
                            oid = Extension.subjectKeyIdentifier;
                            value = new DEROctetString(parseExtensionValue(entry.getValue()));
                            break;
                        case "AuthorityKeyIdentifier":
                            oid = Extension.authorityKeyIdentifier;
                            value = new DEROctetString(parseExtensionValue(entry.getValue()));
                            break;
                        case "KeyUsage":
                            oid = Extension.keyUsage;
                            value = new DEROctetString(parseExtensionValue(entry.getValue()));
                            break;
                        case "ExtendedKeyUsage":
                            oid = Extension.extendedKeyUsage;
                            value = new DEROctetString(parseExtensionValue(entry.getValue()));
                            break;
                        case "BasicConstraints":
                            oid = Extension.basicConstraints;
                            value = new DEROctetString(parseExtensionValue(entry.getValue()));
                            break;
                        default:
                            throw new IllegalArgumentException("Unsupported extension key: " + entry.getKey());
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

    /**
     * Helper method to convert an extension from String to byte array.
     */
    private byte[] parseExtensionValue(String value) {
        if (value.startsWith("[")) {
            value = value.replaceAll("[\\[\\]\\s]", "");
            String[] byteValues = value.split(",");
            byte[] data = new byte[byteValues.length];
            for (int i = 0; i < byteValues.length; i++) {
                data[i] = Byte.parseByte(byteValues[i]);
            }
            return data;
        } else {
            return hexStringToByteArray(value);
        }
    }

    /**
     * Helper method to convert a hex string into a byte array.
     */
    private byte[] hexStringToByteArray(String s) {
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Helper method to serialize a BigInteger (mpint) in SSH format.
     */
    private void appendBigInteger(ASN1EncodableVector vector, BigInteger value, int length) {
        if (value.bitLength() > (length * 8)) {
            throw new IllegalArgumentException("mpint too large");
        }
        byte[] mpintBytes = value.toByteArray();
        vector.add(new DEROctetString(mpintBytes));
    }

    /**
     * Helper method to serialize integer values.
     */
    private void appendInt(ASN1EncodableVector vector, int value, int length) {
        byte[] intBytes = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            intBytes[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        vector.add(new DEROctetString(intBytes));
    }
}
