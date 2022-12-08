<?php

declare(strict_types=1);

namespace TedcryptoOrg\CosmosAccounts\Tests\Util;

use TedcryptoOrg\CosmosAccounts\Tests\BaseTestCase;
use TedcryptoOrg\CosmosAccounts\Util\Bech32;

class Bech32Test extends BaseTestCase
{
    private ?Bech32 $bech32;

    protected function setUp(): void
    {
        $this->bech32 = new Bech32();
    }

    public function testDecode()
    {
        $this->assertSame(
            [
                'cosmos',
                [
                    4, 11, 3, 15, 19, 28, 18, 31, 18, 3, 21, 21, 11, 30, 22, 14,
                    10, 12, 23, 25, 20, 26, 26, 25, 24, 18, 2, 7, 27, 11, 19, 7,
                ]
            ],
            $this->bech32->decode('cosmos1ytr0nujljr44t7kw2vhe566ecjz8mtn8n2v7xy')
        );
    }

    /**
     * @dataProvider provideEncode
     */
    public function testEncode(string $prefix, $dataChars, string $expected)
    {
        $this->assertSame($expected, $this->bech32->encode($prefix, $dataChars));
    }

    public function provideEncode(): array
    {
        $dataChars = [
            4, 11, 3, 15, 19, 28, 18, 31, 18, 3, 21, 21, 11, 30, 22, 14,
            10, 12, 23, 25, 20, 26, 26, 25, 24, 18, 2, 7, 27, 11, 19, 7,
        ];
        return [
            [
                'prefix' => 'cosmos',
                'dataChars' => $dataChars,
                'expected' => 'cosmos1ytr0nujljr44t7kw2vhe566ecjz8mtn8n2v7xy',
            ],
            [
                'prefix' => 'osmo',
                'dataChars' => $dataChars,
                'expected' => 'osmo1ytr0nujljr44t7kw2vhe566ecjz8mtn8m3lwsk',
            ],
            [
                'prefix' => 'bitsong',
                'dataChars' => $dataChars,
                'expected' => 'bitsong1ytr0nujljr44t7kw2vhe566ecjz8mtn8lr7kyt',
            ],
            [
                'prefix' => 'akash',
                'dataChars' => $dataChars,
                'expected' => 'akash1ytr0nujljr44t7kw2vhe566ecjz8mtn873pel7',
            ]
        ];
    }
}