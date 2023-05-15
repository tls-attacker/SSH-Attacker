/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import cc.redberry.rings.poly.univar.UnivariateDivision;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZ64;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

public final class Short {
    private final SntrupParameterSet set;
    private final UnivariatePolynomialZ64 shrt;
    private final UnivariatePolynomialZ64 mod;

    private Short(SntrupParameterSet set) {
        super();
        this.set = set;
        mod = UnivariatePolynomialZ64.parse("x^" + set.getP() + "-x-1");
        shrt = generateShort();
        assert isShort(shrt.stream().toArray(), set);
    }

    private Short(
            SntrupParameterSet set, UnivariatePolynomialZ64 shrt, UnivariatePolynomialZ64 mod) {
        super();
        this.set = set;
        this.mod = mod;
        this.shrt = shrt;
        assert isShort(shrt.stream().toArray(), set);
    }

    public SntrupParameterSet getSet() {
        return set;
    }

    public UnivariatePolynomialZ64 getShrt() {
        return shrt.copy();
    }

    public static Short createRandomShort(SntrupParameterSet set) {
        return new Short(set);
    }

    public LongStream stream() {
        return shrt.stream().map(l -> l == 2 ? -1 : l);
    }

    public static Short createShort(SntrupParameterSet set, long[] coefficients) {
        UnivariatePolynomialZ64 mod = UnivariatePolynomialZ64.parse("x^" + set.getP() + "-x-1");
        UnivariatePolynomialZ64 tmp =
                UnivariateDivision.remainder(
                        UnivariatePolynomialZ64.create(coefficients), mod, false);
        if (isShort(tmp.stream().toArray(), set)) {
            return new Short(set, tmp, mod);
        }
        throw new IllegalArgumentException("Could not create Short with given coefficients");
    }

    public static boolean isShort(long[] coefficients, SntrupParameterSet set) {
        return isWeightW(coefficients, set.getW()) && isSmall(coefficients);
    }

    private static boolean isWeightW(long[] coefficients, int w) {
        long count = Arrays.stream(coefficients).filter(coef -> Math.abs(coef) > 0).count();
        return count == w;
    }

    private static boolean isSmall(long[] coefficients) {
        return Arrays.stream(coefficients).filter(coef -> Math.abs(coef) > 1).findFirst().isEmpty();
    }

    private UnivariatePolynomialZ64 generateShort() {
        int[] mask = new int[set.getP()];
        long[] tmp = new long[set.getP()];
        Random rand = new Random();

        for (int i = 0; i < set.getW(); i++) {
            mask[i] = rand.nextInt(2) + 1;
        }

        for (int i = 0; i < set.getP(); i++) {
            int rN = rand.nextInt();
            tmp[i] = rN ^ rN & 0b11 ^ mask[i];
        }
        Arrays.sort(tmp);
        tmp = Arrays.stream(tmp).map(l -> (l & 0b11) == 0b10 ? -1 : l & 0b11).toArray();
        return UnivariateDivision.remainder(UnivariatePolynomialZ64.create(tmp), mod, false);
    }

    public byte[] encode() {
        ArrayList<Integer> coefficients =
                shrt.stream()
                        .mapToInt(l -> Long.valueOf(l + 1).intValue())
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));
        while (coefficients.size() < set.getP()) {
            coefficients.add(1);
        }
        while (coefficients.size() < 4 * Math.ceil(set.getP() / 4.0)) {
            coefficients.add(0);
        }

        ArrayList<Integer> encodedCoefficients =
                IntStream.range(0, coefficients.size() / 4)
                        .map(x -> 4 * x)
                        .map(
                                x ->
                                        coefficients.get(x)
                                                + coefficients.get(x + 1) * 4
                                                + coefficients.get(x + 2) * 16
                                                + coefficients.get(x + 3) * 64)
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        byte[] res = new byte[encodedCoefficients.size()];
        for (int i = 0; i < encodedCoefficients.size(); i++) {
            res[i] = (byte) encodedCoefficients.get(i).intValue();
        }
        return res;
    }

    public static Short decode(SntrupParameterSet set, byte[] encodedBytes) {
        int[] encodedCoefficients = new int[encodedBytes.length];
        for (int i = 0; i < encodedBytes.length; i++) {
            encodedCoefficients[i] = encodedBytes[i] & 0xff;
        }

        long[] decodedCoefficients =
                IntStream.range(0, set.getP())
                        .mapToLong(
                                i ->
                                        (long) (encodedCoefficients[i / 4] / Math.pow(4, i % 4) % 4)
                                                - 1)
                        .toArray();

        return createShort(set, decodedCoefficients);
    }

    @Override
    public String toString() {
        return shrt.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Short aShort = (Short) obj;
        return set == aShort.set && Objects.equals(shrt, aShort.shrt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(set, shrt);
    }
}
