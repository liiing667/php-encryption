<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception\IOException;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class FileIdentityTest extends TestCase
{
    private $key;
    private static $TEMP_DIR;

    public function set_up()
    {
        self::$TEMP_DIR = __DIR__ . '/File/tmp';
        if (! \is_dir(self::$TEMP_DIR)) {
            \mkdir(self::$TEMP_DIR, 0777, true);
        }

        $this->key = Key::createNewRandomKey();
    }

    public function tear_down()
    {
        foreach ((array) \glob(self::$TEMP_DIR . '/*') as $file) {
            if (\is_link($file) || \is_file($file)) {
                \unlink($file);
            }
        }
        if (\is_dir(self::$TEMP_DIR . '/sub')) {
            \rmdir(self::$TEMP_DIR . '/sub');
        }
        \rmdir(self::$TEMP_DIR);
    }

    /**
     * A hard link refers to the same inode through a different path string,
     * so writing output into it must be refused instead of truncating the
     * input file.
     *
     * @dataProvider fileOperationProvider
     */
    public function testFileIdentityRejectsHardLink($operation)
    {
        $input  = $this->createInputFile($operation, 'input');
        $linked = self::$TEMP_DIR . '/hardlink';
        \link($input, $linked);

        $this->assertNotSame($input, $linked);
        $this->assertNotSame(\realpath($input), \realpath($linked));
        $this->assertSame(\fileinode($input), \fileinode($linked));

        $this->assertOperationIsRefused($operation, $input, $linked);
        $this->assertFileNotTruncated($input, $operation);
    }

    /**
     * A symbolic link resolving to the input file must be refused.
     *
     * @dataProvider fileOperationProvider
     */
    public function testFileIdentityRejectsSymbolicLink($operation)
    {
        $input  = $this->createInputFile($operation, 'input');
        $linked = self::$TEMP_DIR . '/symlink';
        \symlink(\basename($input), $linked);

        $this->assertTrue(\is_link($linked));

        $this->assertOperationIsRefused($operation, $input, $linked);
        $this->assertFileNotTruncated($input, $operation);
    }

    /**
     * Passing the exact same path twice must be refused without truncation.
     *
     * @dataProvider fileOperationProvider
     */
    public function testFileIdentityRejectsSamePath($operation)
    {
        $input = $this->createInputFile($operation, 'input');

        $this->assertOperationIsRefused($operation, $input, $input);
        $this->assertFileNotTruncated($input, $operation);
    }

    /**
     * A path string that differs but resolves to the input file must be
     * refused.
     *
     * @dataProvider fileOperationProvider
     */
    public function testFileIdentityRejectsResolvingPathAlias($operation)
    {
        $input   = $this->createInputFile($operation, 'input');
        $aliased = self::$TEMP_DIR . '/sub/../' . \basename($input);
        \mkdir(self::$TEMP_DIR . '/sub');

        $this->assertNotSame($input, $aliased);

        $this->assertOperationIsRefused($operation, $input, $aliased);
        $this->assertFileNotTruncated($input, $operation);
    }

    /**
     * A non-existent output file is created normally, without touching the
     * input file.
     *
     * @dataProvider fileOperationProvider
     */
    public function testFileIdentityAllowsNonExistentOutput($operation)
    {
        $input  = $this->createInputFile($operation, 'input');
        $output = self::$TEMP_DIR . '/output';

        $this->invokeOperation($operation, $input, $output);

        $this->assertFileExists($output);
        $this->assertNotEquals(\fileinode($input), \fileinode($output));
        $this->assertGreaterThan(0, \filesize($input));
    }

    /**
     * A distinct existing output file keeps its original overwrite behavior.
     */
    public function testFileIdentityOverwritesDistinctExistingOutput()
    {
        $input  = self::$TEMP_DIR . '/input';
        $output = self::$TEMP_DIR . '/output';
        \file_put_contents($input, \str_repeat('F', 1024));
        \file_put_contents($output, 'stale contents');

        File::encryptFile($input, $output, $this->key);

        $this->assertFileExists($output);
        $this->assertNotSame('stale contents', \file_get_contents($output));
        $this->assertSame(\str_repeat('F', 1024), \file_get_contents($input));
    }

    public static function fileOperationProvider()
    {
        return [
            'encrypt' => ['encrypt'],
            'decrypt' => ['decrypt'],
        ];
    }

    private function assertOperationIsRefused($operation, $input, $output)
    {
        try {
            $this->invokeOperation($operation, $input, $output);
            $this->fail('Expected an IOException because input and output are the same file.');
        } catch (IOException $ex) {
            $this->assertSame('Input and output filenames must be different.', $ex->getMessage());
        }
    }

    private function assertFileNotTruncated($path, $operation)
    {
        $this->assertGreaterThan(0, \filesize($path));
        if ($operation === 'encrypt') {
            $this->assertSame(\str_repeat('A', 1024), \file_get_contents($path));
        }
    }

    private function invokeOperation($operation, $input, $output)
    {
        if ($operation === 'encrypt') {
            File::encryptFile($input, $output, $this->key);
        } else {
            File::decryptFile($input, $output, $this->key);
        }
    }

    /**
     * Creates a valid input file for the requested operation: plaintext for
     * encryption and a valid ciphertext for decryption.
     *
     * @param string $operation
     * @param string $name
     * @return string
     */
    private function createInputFile($operation, $name)
    {
        $path = self::$TEMP_DIR . '/' . $name;
        if ($operation === 'encrypt') {
            \file_put_contents($path, \str_repeat('A', 1024));
            return $path;
        }

        $plaintext = self::$TEMP_DIR . '/plaintext-source';
        \file_put_contents($plaintext, \str_repeat('Z', 1024));
        File::encryptFile($plaintext, $path, $this->key);
        return $path;
    }
}
