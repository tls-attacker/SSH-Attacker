/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import cc.redberry.rings.IntegersZp64;
import cc.redberry.rings.poly.PolynomialMethods;
import cc.redberry.rings.poly.univar.UnivariateDivision;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

@SuppressWarnings("StandardVariableNames")
public class R3 {
    private final SntrupParameterSet set;
    private UnivariatePolynomialZp64 r3;
    private final UnivariatePolynomialZp64 mod;

    public R3(SntrupParameterSet set, long[] coefficient) {
        super();
        this.set = set;
        mod = genereateMod(set);
        setR3(coefficient);
    }

    private R3(SntrupParameterSet set, UnivariatePolynomialZp64 r3) {
        super();
        this.set = set;
        this.r3 = r3;
        mod = genereateMod(set);
    }

    private static UnivariatePolynomialZp64 genereateMod(SntrupParameterSet set) {
        return UnivariatePolynomialZp64.parse("x^" + set.getP() + "-x-1", new IntegersZp64(3), "x");
    }

    public SntrupParameterSet getSet() {
        return set;
    }

    public UnivariatePolynomialZp64 getR3() {
        return r3.clone();
    }

    public UnivariatePolynomialZp64 getMod() {
        return mod.clone();
    }

    public void setR3(long[] coefficients) {
        r3 =
                UnivariateDivision.remainder(
                        UnivariatePolynomialZp64.create(3, coefficients), mod, false);
    }

    public static boolean isR3(long[] coefficients) {
        return Arrays.stream(coefficients).filter(c -> Math.abs(c) > 1).findAny().isEmpty();
    }

    public LongStream stream() {
        return r3.stream().map(l -> l == 2 ? -1 : l);
    }

    public static Optional<R3> getInverseInR3(SntrupParameterSet set, R candidate) {
        UnivariatePolynomialZp64 candidateR3 =
                UnivariatePolynomialZp64.create(3, candidate.stream().toArray());
        UnivariatePolynomialZp64[] xgcd =
                PolynomialMethods.PolynomialExtendedGCD(candidateR3, genereateMod(set));
        if (UnivariateDivision.remainder(
                                xgcd[1].clone().multiply(candidateR3), genereateMod(set), false)
                        .compareTo(UnivariatePolynomialZp64.one(3))
                == 0) {
            return Optional.of(new R3(set, xgcd[1]));
        }
        return Optional.empty();
    }

    public static R3 multiply(R3 r3_1, R3 r3_2) {
        return new R3(
                r3_1.set,
                UnivariateDivision.remainder(
                        r3_1.getR3().multiply(r3_2.getR3()), r3_1.getMod(), true));
    }

    public byte[] encode() {

        ArrayList<Integer> coefficients =
                stream()
                        .mapToInt(c -> Long.valueOf(c + 1).intValue())
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        while (coefficients.size() < 4 * Math.ceil(set.getP() / 4.0)) {
            coefficients.add(1);
        }

        ArrayList<Integer> encdodedCoefficients =
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

        byte[] res = new byte[encdodedCoefficients.size()];
        for (int i = 0; i < encdodedCoefficients.size(); i++) {
            res[i] = (byte) encdodedCoefficients.get(i).intValue();
        }
        return res;
    }

    public static R3 decode(SntrupParameterSet set, byte[] encodedBytes) {
        int[] encdodedCoefficients = new int[encodedBytes.length];
        for (int i = 0; i < encodedBytes.length; i++) {
            encdodedCoefficients[i] = encodedBytes[i] & 0xff;
        }
        long[] decodedCoefficients =
                IntStream.range(0, set.getP())
                        .mapToLong(
                                i ->
                                        (long)
                                                        (encdodedCoefficients[i / 4]
                                                                / Math.pow(4, i % 4)
                                                                % 4)
                                                - 1)
                        .toArray();

        return new R3(set, decodedCoefficients);
    }

    @Override
    public String toString() {
        return r3.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        R3 r31 = (R3) obj;
        return set == r31.set && Objects.equals(r3, r31.r3);
    }

    @Override
    public int hashCode() {
        return Objects.hash(set, r3);
    }
}
