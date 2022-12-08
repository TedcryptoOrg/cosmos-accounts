<?php

declare(strict_types=1);

namespace TedcryptoOrg\CosmosAccounts\Util;

use TedcryptoOrg\CosmosAccounts\Exception\Bech32Exception;

/**
 * This is a copy of https://github.com/Bit-Wasp/bech32/blob/master/src/bech32.php
 * with small adaptations
 */
class Bech32
{
    private const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    private const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    private const CHARKEY_KEY = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
        1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
        1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1
    ];

    public static function encode(string $hrp, array $combinedDataChars): string
    {
        $checksum = self::createChecksum($hrp, $combinedDataChars);
        $characters = \array_merge($combinedDataChars, $checksum);

        $encoded = [];
        for ($i = 0, $n = count($characters); $i < $n; $i++) {
            $encoded[$i] = self::CHARSET[$characters[$i]];
        }

        return "{$hrp}1" . \implode('', $encoded);
    }

    /**
     * @return array - returns [$hrp, $dataChars]
     *
     * @throws Bech32Exception
     */
    public static function decodeRaw(string $bech32EncodedString): array
    {
        $length = \strlen($bech32EncodedString);
        if ($length < 8) {
            throw new Bech32Exception("Bech32 string is too short");
        }

        $chars = array_values(unpack('C*', $bech32EncodedString));

        $haveUpper = false;
        $haveLower = false;
        $positionOne = -1;

        for ($i = 0; $i < $length; $i++) {
            $x = $chars[$i];
            if ($x < 33 || $x > 126) {
                throw new Bech32Exception('Out of range character in bech32 string');
            }

            if ($x >= 0x61 && $x <= 0x7a) {
                $haveLower = true;
            }

            if ($x >= 0x41 && $x <= 0x5a) {
                $haveUpper = true;
                $x = $chars[$i] = $x + 0x20;
            }

            // find location of last '1' character
            if ($x === 0x31) {
                $positionOne = $i;
            }
        }

        if ($haveUpper && $haveLower) {
            throw new Bech32Exception('Data contains mixture of higher/lower case characters');
        }

        if ($positionOne === -1) {
            throw new Bech32Exception("Missing separator character");
        }

        if ($positionOne < 1) {
            throw new Bech32Exception("Empty HRP");
        }

        if (($positionOne + 7) > $length) {
            throw new Bech32Exception('Too short checksum');
        }

        $hrp = \pack("C*", ...\array_slice($chars, 0, $positionOne));

        $data = [];
        for ($i = $positionOne + 1; $i < $length; $i++) {
            $data[] = ($chars[$i] & 0x80) ? -1 : self::CHARKEY_KEY[$chars[$i]];
        }

        if (!self::verifyChecksum($hrp, $data)) {
            throw new Bech32Exception('Invalid bech32 checksum');
        }

        return [$hrp, array_slice($data, 0, -6)];
    }

    /**
     * Validates a bech32 string and returns [$hrp, $dataChars] if
     * the conversion was successful. An exception is thrown on invalid
     * data.
     *
     * @return array - returns [$hrp, $dataChars]
     */
    public static function decode($bech32EncodedString): array
    {
        $length = strlen($bech32EncodedString);
        if ($length > 90) {
            throw new Bech32Exception('Bech32 string cannot exceed 90 characters in length');
        }

        return self::decodeRaw($bech32EncodedString);
    }

    private static function polyMod(array $values, int $numValues): int
    {
        $chk = 1;
        for ($i = 0; $i < $numValues; $i++) {
            $top = $chk >> 25;
            $chk = ($chk & 0x1ffffff) << 5 ^ $values[$i];

            for ($j = 0; $j < 5; $j++) {
                $value = (($top >> $j) & 1) ? self::GENERATOR[$j] : 0;
                $chk ^= $value;
            }
        }

        return $chk;
    }

    /**
     * Expands the human-readable part into a character array for checksumming.
     *
     * @return int[]
     */
    private static function hrpExpand(string $hrp, int $hrpLen): array
    {
        $expand1 = [];
        $expand2 = [];
        for ($i = 0; $i < $hrpLen; $i++) {
            $o = \ord($hrp[$i]);
            $expand1[] = $o >> 5;
            $expand2[] = $o & 31;
        }

        return \array_merge($expand1, [0], $expand2);
    }

    private static function createChecksum(string $hrp, array $convertedDataChars): array
    {
        $values = \array_merge(self::hrpExpand($hrp, \strlen($hrp)), $convertedDataChars);
        $polyMod = self::polyMod(\array_merge($values, [0, 0, 0, 0, 0, 0]), \count($values) + 6) ^ 1;
        $results = [];
        for ($i = 0; $i < 6; $i++) {
            $results[$i] = ($polyMod >> 5 * (5 - $i)) & 31;
        }

        return $results;
    }

    /**
     * Verifies the checksum given $hrp and $convertedDataChars.
     */
    private static function verifyChecksum(string $hrp, array $convertedDataChars): bool
    {
        $expandHrp = self::hrpExpand($hrp, \strlen($hrp));
        $r = \array_merge($expandHrp, $convertedDataChars);
        $poly = self::polyMod($r, \count($r));
        return $poly === 1;
    }
}
