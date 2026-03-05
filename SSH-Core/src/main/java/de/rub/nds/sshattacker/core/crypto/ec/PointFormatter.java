/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.EcPointFormat;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class PointFormatter {

    private static final Logger LOGGER = LogManager.getLogger();

    static final byte[] uncompressedFormat = {0x04};
    static final byte[] compressedFormat = {0x03};
    static final byte[] inverseAffineCompressedFormat = {0x02};

    public static byte[] formatToByteArray(NamedEcGroup group, Point point, EcPointFormat format) {
        if (point.isAtInfinity()) {
            return new byte[1];
        }
        int elementLength =
                ArrayConverter.bigIntegerToByteArray(point.getFieldX().getModulus()).length;
        if (group != NamedEcGroup.CURVE448 && group != NamedEcGroup.CURVE25519) {
            switch (format) {
                case UNCOMPRESSED:
                    return ArrayConverter.concatenate(
                            uncompressedFormat,
                            ArrayConverter.bigIntegerToNullPaddedByteArray(
                                    point.getFieldX().getData(), elementLength),
                            ArrayConverter.bigIntegerToNullPaddedByteArray(
                                    point.getFieldY().getData(), elementLength));
                case ANSIX962_COMPRESSED_CHAR2:
                case ANSIX962_COMPRESSED_PRIME:
                    EllipticCurve curve = CurveFactory.getCurve(group);
                    if (curve.createAPointOnCurve(point.getFieldX().getData())
                            .getFieldY()
                            .getData()
                            .equals(point.getFieldY().getData())) {
                        return ArrayConverter.concatenate(
                                compressedFormat,
                                ArrayConverter.bigIntegerToNullPaddedByteArray(
                                        point.getFieldX().getData(), elementLength));
                    } else {
                        return ArrayConverter.concatenate(
                                inverseAffineCompressedFormat,
                                ArrayConverter.bigIntegerToNullPaddedByteArray(
                                        point.getFieldX().getData(), elementLength));
                    }
                default:
                    throw new UnsupportedOperationException("Unsupported PointFormat: " + format);
            }
        } else {
            return ArrayConverter.bigIntegerToNullPaddedByteArray(
                    point.getFieldX().getData(), elementLength);
        }
    }

    public static byte[] toRawFormat(Point point) {
        if (point.isAtInfinity()) {
            return new byte[1];
        }
        int elementLength =
                ArrayConverter.bigIntegerToByteArray(point.getFieldX().getModulus()).length;
        return ArrayConverter.concatenate(
                ArrayConverter.bigIntegerToNullPaddedByteArray(
                        point.getFieldX().getData(), elementLength),
                ArrayConverter.bigIntegerToNullPaddedByteArray(
                        point.getFieldY().getData(), elementLength));
    }

    public static Point fromRawFormat(NamedEcGroup group, byte[] pointBytes) {
        EllipticCurve curve = CurveFactory.getCurve(group);
        int elementLength = ArrayConverter.bigIntegerToByteArray(curve.getModulus()).length;
        if (pointBytes.length < elementLength * 2) {
            LOGGER.warn("Cannot decode byte[] to point of {}. Returning Basepoint", group);
            return curve.getBasePoint();
        }
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pointBytes);
        byte[] coordX = new byte[elementLength];
        byte[] coordY = new byte[elementLength];
        try {
            // noinspection ResultOfMethodCallIgnored
            inputStream.read(coordX);
            // noinspection ResultOfMethodCallIgnored
            inputStream.read(coordY);
        } catch (IOException ex) {
            LOGGER.warn("Could not read from byteArrayStream. Returning Basepoint", ex);
            return curve.getBasePoint();
        }
        return curve.getPoint(new BigInteger(1, coordX), new BigInteger(1, coordY));
    }

    public static Point formatFromByteArray(NamedEcGroup group, byte[] compressedPoint) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(compressedPoint);
        EllipticCurve curve = CurveFactory.getCurve(group);
        int elementLength = ArrayConverter.bigIntegerToByteArray(curve.getModulus()).length;
        if (compressedPoint.length == 0) {
            LOGGER.warn("Could not parse point. Point is empty. Returning Basepoint");
            return curve.getBasePoint();
        }
        if (group != NamedEcGroup.CURVE448 && group != NamedEcGroup.CURVE25519) {
            int pointFormat = inputStream.read();
            byte[] coordX = new byte[elementLength];
            switch (pointFormat) {
                case 2:
                case 3:
                    if (compressedPoint.length != elementLength + 1) {
                        LOGGER.warn(
                                "Could not parse point. Point needs to be {} bytes long, but was {}bytes long. Returning Basepoint",
                                elementLength + 1,
                                compressedPoint.length);

                        return curve.getBasePoint();
                    }
                    try {
                        // noinspection ResultOfMethodCallIgnored
                        inputStream.read(coordX);
                    } catch (IOException ex) {
                        LOGGER.warn("Could not read from byteArrayStream. Returning Basepoint", ex);
                        return curve.getBasePoint();
                    }
                    Point decompressedPoint = curve.createAPointOnCurve(new BigInteger(1, coordX));
                    if (pointFormat == 2) {
                        decompressedPoint = curve.inverseAffine(decompressedPoint);
                    }
                    return decompressedPoint;

                case 4:
                    if (compressedPoint.length != elementLength * 2 + 1) {
                        LOGGER.warn(
                                "Could not parse point. Point needs to be {} bytes long, but was {}bytes long. Returning Basepoint",
                                elementLength * 2 + 1,
                                compressedPoint.length);
                        return curve.getBasePoint();
                    }

                    byte[] coordY = new byte[elementLength];
                    try {
                        // noinspection ResultOfMethodCallIgnored
                        inputStream.read(coordX);
                        // noinspection ResultOfMethodCallIgnored
                        inputStream.read(coordY);
                    } catch (IOException ex) {
                        LOGGER.warn("Could not read from byteArrayStream. Returning Basepoint", ex);
                        return curve.getBasePoint();
                    }
                    return curve.getPoint(new BigInteger(1, coordX), new BigInteger(1, coordY));

                default:
                    throw new UnsupportedOperationException(
                            "Unsupported PointFormat: " + pointFormat);
            }
        }
        throw new UnsupportedOperationException("Unsupported NamedGroup: " + group);
    }

    private PointFormatter() {
        super();
    }
}
