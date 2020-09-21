<?php
/***
 * PHP Implementation of the ICE encryption algorithm (http://www.darkside.com.au/ice/)
 *
 * Usage:
 * $iceKey = new IceKey(0, array(0x11, 0x22, 0x33, 0x44, 0x54, 0x55, 0x66, 0x77));
 * $bytes = array(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10);
 * $encryptedBytes = iceKey->encrypt($bytes);
 * $decryptedBytes = iceKey->decrypt($cryptedBytes);
 * 
 * @author Matthew Kwan
 * @author ANZO (PHP Implementation)
 */

namespace an3o\IceKey;

class IceKey {
    private $size;
    private $rounds;
    private $keySchedule;

    private $spBox;

    private $sMod = array(
        array(333, 313, 505, 369),
        array(379, 375, 319, 391),
        array(361, 445, 451, 397),
        array(397, 425, 395, 505));

    private $sXor = array(
        array(0x83, 0x85, 0x9b, 0xcd),
        array(0xcc, 0xa7, 0xad, 0x41),
        array(0x4b, 0x2e, 0xd4, 0x33),
        array(0xea, 0xcb, 0x2e, 0x04)
    );

    public $pBox = array(
        0x00000001, 0x00000080, 0x00000400, 0x00002000,
        0x00080000, 0x00200000, 0x01000000, 0x40000000,
        0x00000008, 0x00000020, 0x00000100, 0x00004000,
        0x00010000, 0x00800000, 0x04000000, 0x20000000,
        0x00000004, 0x00000010, 0x00000200, 0x00008000,
        0x00020000, 0x00400000, 0x08000000, 0x10000000,
        0x00000002, 0x00000040, 0x00000800, 0x00001000,
        0x00040000, 0x00100000, 0x02000000, 0x80000000);

    public $keyrot = array(0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2);

    /***
     * IceKey constructor.
     * @param int $level
     * @param $key array
     */
    function __construct($level, $key) {
        $this->spBoxInit();
        if ($level < 1) {
            $this->size = 1;
            $this->rounds = 8;
        } else {
            $this->size = $level;
            $this->rounds = $level * 16;
        }

        $this->keySchedule = array_fill(0, $this->rounds, array_fill(0, 3, 0));
        $this->setKey($key);
    }

    /***
     * Set the key schedule of an ICE key.
     * @param $key array
     */
    private function setKey($key) {
        $kb = array_fill(0, 4, 0);

        if ($this->rounds == 8) {
            for ($i=0; $i<4; $i++)
                $kb[3 - $i] = (($key[$i*2] & 0xff) << 8)
                    | ($key[$i*2 + 1] & 0xff);

            $this->scheduleBuild($kb, 0, 0);
            return;
        }

        for ($i = 0; $i < $this->size; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $kb[3 - $j] = (($key[$i * 8 + $j * 2] & 0xff) << 8)
                    | ($key[$i * 8 + $j * 2 + 1] & 0xff);
            }

            $this->scheduleBuild($kb, $i * 8, 0);
            $this->scheduleBuild($kb, $this->rounds - 8 - $i * 8, 8);
        }
    }

    /***
     * Encrypt a block of 8 bytes of data.
     * @param $plainBytes array bytes to encrypt
     * @return array encrypted bytes
     */
    public function encryptBlock($plainBytes) {
        $ciphertext = array_fill(0, count($plainBytes), 0);
        $r = 0;
        $l = 0;

        for ($i = 0; $i < 4; $i++) {
            $l |= ($plainBytes[$i] & 0xff) << (24 - $i * 8);
            $r |= ($plainBytes[$i + 4] & 0xff) << (24 - $i * 8);
        }

        for ($i = 0; $i < $this->rounds; $i += 2) {
            $l ^= $this->roundFunc($r, $this->keySchedule[$i]);
            $r ^= $this->roundFunc($l, $this->keySchedule[$i + 1]);
        }

        for ($i = 0; $i < 4; $i++) {
            $ciphertext[3 - $i] = ($r & 0xff);
            $ciphertext[7 - $i] = ($l & 0xff);

            $r = $this->rrr($r, 8);
            $l = $this->rrr($l, 8);;
        }
        return $ciphertext;
    }

    /***
     * @param $plainBytes array bytes to encrypt
     * @return array encrypted bytes
     */
    public function encrypt($plainBytes) {
        $alignedLength = (int)((count($plainBytes) + $this->blockSize() - 1) / $this->blockSize()) * $this->blockSize();
        $alignedPlainBytes = array_pad($plainBytes, $alignedLength, 0);
        $alignedCipherBytes = array_fill(0, $alignedLength, 0);

        for ($byteIndex = 0; $byteIndex < count($alignedCipherBytes); $byteIndex += $this->blockSize()) {
            $plainBytesBlock = array_slice($alignedPlainBytes, $byteIndex, $this->blockSize());
            $cipherBytesBlock = $this->encryptBlock($plainBytesBlock);

            for ($i = 0; $i < $this->blockSize(); $i++) {
                $alignedCipherBytes[$byteIndex + $i] = $cipherBytesBlock[$i];
            }
        }
        return $alignedCipherBytes;
    }

    /***
     * Decrypt a block of 8 bytes of data.
     * @param $cipherBytes array bytes to decrypt
     * @return array decrypted bytes
     */
    private function decryptBlock($cipherBytes) {
        $plainBytes = array_fill(0, count($cipherBytes), 0);
        $r = 0;
        $l = 0;

        for ($i = 0; $i < 4; $i++) {
            $l |= ($cipherBytes[$i] & 0xff) << (24 - $i*8);
            $r |= ($cipherBytes[$i + 4] & 0xff) << (24 - $i*8);
        }

        for ($i = $this->rounds - 1; $i > 0; $i -= 2) {
            $l ^= $this->roundFunc($r, $this->keySchedule[$i]);
            $r ^= $this->roundFunc($l, $this->keySchedule[$i - 1]);
        }

        for ($i = 0; $i < 4; $i++) {
            $plainBytes[3 - $i] = ($r & 0xff); // To byte
            $plainBytes[7 - $i] = ($l & 0xff); // To byte

            $r = $this->rrr($r, 8);
            $l = $this->rrr($l, 8);;
        }
        return $plainBytes;
    }

    /***
     * @param $cipherBytes array bytes to decrypt
     * @return array decrypted bytes
     */
    public function decrypt($cipherBytes) {
        $plainBytes = array_fill(0, count($cipherBytes), 0);
        for ($byteIndex = 0; $byteIndex < count($cipherBytes); $byteIndex += $this->blockSize()) {
            $cipherBytesBlock = array_slice($cipherBytes, $byteIndex, $this->blockSize());
            $plainBytesBlock = $this->decryptBlock($cipherBytesBlock);

            for ($i = 0; $i < $this->blockSize(); $i++) {
                $plainBytes[$byteIndex + $i] = $plainBytesBlock[$i];
            }
        }
        return $plainBytes;
    }

    /***
     * Clear the key schedule to prevent memory snooping.
     */
    public function clear() {
        for ($i = 0; $i < $this->rounds; $i++) {
            for ($j = 0; $j < 3; $j++) {
                $this->keySchedule[$i][$j] = 0;
            }
        }
    }

    /***
     * Set 8 rounds [n, n+7] of the key schedule of an ICE key.
     * @param $kb array
     * @param $n int
     * @param $krot_idx int
     */
    private function scheduleBuild($kb, $n, $krot_idx) {
        for ($i = 0; $i < 8; $i++) {
            $kr = $this->keyrot[$krot_idx + $i];

            for ($j = 0; $j < 3; $j++)
                $this->keySchedule[$n + $i][$j] = 0;

            for ($j = 0; $j < 15; $j++) {
                $curr_sk = $j % 3;

                for ($k = 0; $k < 4; $k++) {
                    $curr_kb = $kb[($kr + $k) & 3];
                    $bit = $curr_kb & 1;

                    $this->keySchedule[$n + $i][$curr_sk] = ($this->keySchedule[$n + $i][$curr_sk] << 1) | $bit;
                    $kb[($kr + $k) & 3] = $this->rrr($curr_kb,1) | (($bit ^ 1) << 15);
                }
            }
        }
    }

    /***
     * The single round ICE f function.
     * @param $p int
     * @param $subkey array
     * @return int
     */
    private function roundFunc($p, $subkey) {
        $tl = ($this->rrr($p,16) & 0x3ff) | (($this->rrr($p, 14) | ($p << 18)) & 0xffc00);
        $tr = ($p & 0x3ff) | (($p << 2) & 0xffc00);

        $al = $subkey[2] & ($tl ^ $tr);
        $ar = $al ^ $tr;
        $al ^= $tl;

        $al ^= $subkey[0];
        $ar ^= $subkey[1];

        return ($this->spBox[0][$this->rrr($al, 10)] | $this->spBox[1][$al & 0x3ff]
            | $this->spBox[2][$this->rrr($ar, 10)] | $this->spBox[3][$ar & 0x3ff]);
    }

    /***
     * 8-bit Galois Field multiplication of a by b, modulo m.
     * Just like arithmetic multiplication, except that
     * additions and subtractions are replaced by XOR.
     * @param $a int
     * @param $b int
     * @param $m int
     * @return int
     */
    private function gf_mult($a, $b, $m) {
        $res = 0;

        while ($b != 0) {
            if (($b & 1) != 0) {
                $res ^= $a;
            }

            $a <<= 1;
            $b = $this->rrr($b, 1);

            if ($a >= 256) {
                $a ^= $m;
            }
        }
        return $res;
    }

    /***
     * 8-bit Galois Field exponentiation.
     * Raise the base to the power of 7, modulo m.
     * @param $b int
     * @param $m int
     * @return int
     */
    private function gf_exp7($b, $m) {
        if ($b == 0) {
            return 0;
        }

        $x = $this->gf_mult($b, $b, $m);
        $x = $this->gf_mult($b, $x, $m);
        $x = $this->gf_mult($x, $x, $m);
        return $this->gf_mult($b, $x, $m);
    }

    /***
     * Carry out the ICE 32-bit permutation.
     * @param $x int
     * @return int
     */
    private function perm32($x) {
        $res = 0;
        $i = 0;

        while ($x != 0) {
            if (($x & 1) != 0) {
                $res |= $this->pBox[$i];
            }

            $i++;
            $x = $this->rrr($x, 1);
        }
        return $res;
    }

    /***
     * Initialise the substitution/permutation boxes.
     */
    private function spBoxInit() {
        $this->spBox = array_fill(0, 4, array_fill(0, 1024, 0));

        for ($i = 0; $i < 1024; $i++) {
            $col = $this->rrr($i, 1) & 0xff;
            $row = ($i & 0x1) | ($this->rrr(($i & 0x200), 8));

            $x = $this->gf_exp7($col ^ $this->sXor[0][$row], $this->sMod[0][$row]) << 24;
            $this->spBox[0][$i] = $this->perm32($x);

            $x = $this->gf_exp7($col ^ $this->sXor[1][$row], $this->sMod[1][$row]) << 16;
            $this->spBox[1][$i] = $this->perm32($x);

            $x = $this->gf_exp7($col ^ $this->sXor[2][$row], $this->sMod[2][$row]) << 8;
            $this->spBox[2][$i] = $this->perm32($x);

            $x = $this->gf_exp7($col ^ $this->sXor[3][$row], $this->sMod[3][$row]);
            $this->spBox[3][$i] = $this->perm32($x);
        }
    }

    /***
     * @return int the key size, in bytes.
     */
    public function keySize() {
	    return (int)($this->size * 8);
	}

    /***
     * @return int block size, in bytes.
     */
    public function blockSize() {
	    return 8;
	}

    /**
     * Support for >>> bitwise operator in php x86_64
     * Usage: -1149025787 >>> 0 ---> rrr(-1149025787, 0) === 3145941509
     * @param int $v
     * @param int $n
     * @return int
     */
    function rrr($v, $n) {
        return ($v & 0xFFFFFFFF) >> ($n & 0x1F);
    }
}