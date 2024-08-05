<?php declare(strict_types=1);

namespace Amp\Socket;

use Amp\Socket;
use PHPUnit\Framework\TestCase;

class ServerTlsContextTest extends TestCase
{
    public function minimumVersionDataProvider(): array
    {
        return [
            [ServerTlsContext::TLSv1_0],
            [ServerTlsContext::TLSv1_1],
            [ServerTlsContext::TLSv1_2],
            [ServerTlsContext::TLSv1_3],
        ];
    }

    /**
     * @dataProvider minimumVersionDataProvider
     */
    public function testWithMinimumVersion($version): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withMinimumVersion($version);

        self::assertSame(ServerTlsContext::TLSv1_2, $context->getMinimumVersion());
        self::assertSame($version, $clonedContext->getMinimumVersion());
    }

    public function minimumVersionInvalidDataProvider(): array
    {
        return [
            [-1],
        ];
    }

    /**
     * @dataProvider minimumVersionInvalidDataProvider
     */
    public function testWithMinimumVersionInvalid($version): void
    {
        $this->expectException(\Error::class);
        $this->expectExceptionMessage('Invalid minimum version');

        (new ServerTlsContext)->withMinimumVersion($version);
    }

    public function peerNameDataProvider(): array
    {
        return [
            [null],
            ['test'],
        ];
    }

    /**
     * @dataProvider peerNameDataProvider
     */
    public function testWithPeerName($peerName): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withPeerName($peerName);

        self::assertNull($context->getPeerName());
        self::assertSame($peerName, $clonedContext->getPeerName());
    }

    public function testWithPeerVerification(): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withPeerVerification();

        self::assertFalse($context->hasPeerVerification());
        self::assertTrue($clonedContext->hasPeerVerification());
    }

    public function testWithoutPeerVerification(): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withoutPeerVerification();

        self::assertFalse($context->hasPeerVerification());
        self::assertFalse($clonedContext->hasPeerVerification());
    }

    public function testDefaultPeerNameVerification(): void
    {
        $context = new ServerTlsContext;
        self::assertFalse($context->hasPeerNameVerification());
    }

    public function testWithoutPeerNameVerification(): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withPeerVerification()->withoutPeerNameVerification();

        self::assertTrue($clonedContext->hasPeerVerification());
        self::assertFalse($clonedContext->hasPeerNameVerification());
    }

    public function testContextOptionsWithoutPeerNameVerification(): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withPeerVerification()->withoutPeerNameVerification();
        $options = $clonedContext->toStreamContextArray()['ssl'];

        self::assertTrue($options['verify_peer']);
        self::assertFalse($options['verify_peer_name']);
    }

    public function verifyDepthDataProvider(): array
    {
        return [
            [0],
            [123],
        ];
    }

    /**
     * @dataProvider verifyDepthDataProvider
     */
    public function testWithVerificationDepth($verifyDepth): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withVerificationDepth($verifyDepth);

        self::assertSame(10, $context->getVerificationDepth());
        self::assertSame($verifyDepth, $clonedContext->getVerificationDepth());
    }

    public function verifyDepthInvalidDataProvider(): array
    {
        return [
            [-1],
            [-123],
        ];
    }

    /**
     * @dataProvider verifyDepthInvalidDataProvider
     */
    public function testWithVerificationDepthInvalid($verifyDepth): void
    {
        $this->expectException(\Error::class);
        $this->expectExceptionMessageMatches('/Invalid verification depth (.*), must be greater than or equal to 0/');

        (new ServerTlsContext)->withVerificationDepth($verifyDepth);
    }

    public function ciphersDataProvider(): array
    {
        return [
            ['ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256'],
            ['DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256'],
        ];
    }

    /**
     * @dataProvider ciphersDataProvider
     */
    public function testWithCiphers($ciphers): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withCiphers($ciphers);

        self::assertSame(\OPENSSL_DEFAULT_STREAM_CIPHERS, $context->getCiphers());
        self::assertSame($ciphers, $clonedContext->getCiphers());
    }

    public function caFileDataProvider(): array
    {
        return [
            [null],
            ['test'],
        ];
    }

    /**
     * @dataProvider caFileDataProvider
     */
    public function testWithCaFile($caFile): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withCaFile($caFile);

        self::assertNull($context->getCaFile());
        self::assertSame($caFile, $clonedContext->getCaFile());
    }

    public function caPathDataProvider(): array
    {
        return [
            [null],
            ['test'],
        ];
    }

    /**
     * @dataProvider caPathDataProvider
     */
    public function testWithCaPath($caPath): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withCaPath($caPath);

        self::assertNull($context->getCaPath());
        self::assertSame($caPath, $clonedContext->getCaPath());
    }

    public function testWithPeerCapturing(): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withPeerCapturing();

        self::assertFalse($context->hasPeerCapturing());
        self::assertTrue($clonedContext->hasPeerCapturing());
    }

    public function testWithoutPeerCapturing(): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withoutPeerCapturing();

        self::assertFalse($context->hasPeerCapturing());
        self::assertFalse($clonedContext->hasPeerCapturing());
    }

    public function defaultCertificateDataProvider(): array
    {
        return [
            [null],
            [new Certificate('test')],
        ];
    }

    /**
     * @dataProvider defaultCertificateDataProvider
     */
    public function testWithDefaultCertificate($defaultCertificate): void
    {
        $context = new ServerTlsContext;
        $clonedContext = $context->withDefaultCertificate($defaultCertificate);

        self::assertNull($context->getDefaultCertificate());
        self::assertSame($defaultCertificate, $clonedContext->getDefaultCertificate());
    }

    public function testWithCertificatesErrorWithoutStringKeys(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("Expected an array mapping domain names to Certificate instances");

        (new ServerTlsContext)->withCertificates([new Certificate("/foo/bar")]);
    }

    public function testWithCertificatesErrorWithoutCertificateInstances(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("Expected an array of Certificate instances");

        (new ServerTlsContext)->withCertificates(["example.com" => "/foo/bar"]);
    }

    public function invalidSecurityLevelDataProvider(): array
    {
        return [
            [-1],
            [6],
        ];
    }

    /**
     * @dataProvider invalidSecurityLevelDataProvider
     */
    public function testWithSecurityLevelInvalid($level): void
    {
        $this->expectException(\Error::class);
        $this->expectExceptionMessage("Invalid security level ({$level}), must be between 0 and 5.");

        (new ServerTlsContext)->withSecurityLevel($level);
    }

    public function validSecurityLevelDataProvider(): array
    {
        return [
            [0],
            [1],
            [2],
            [3],
            [4],
            [5],
        ];
    }

    /**
     * @dataProvider validSecurityLevelDataProvider
     */
    public function testWithSecurityLevelValid($level): void
    {
        if (\OPENSSL_VERSION_NUMBER >= 0x10100000) {
            $value = (new ServerTlsContext)
                ->withSecurityLevel($level)
                ->getSecurityLevel();

            self::assertSame($level, $value);
        } else {
            $this->expectException(\Error::class);
            $this->expectExceptionMessage("Can't set a security level, as PHP is compiled with OpenSSL < 1.1.0.");

            (new ServerTlsContext)->withSecurityLevel($level);
        }
    }

    public function testWithSecurityLevelDefaultValue(): void
    {
        if (\OPENSSL_VERSION_NUMBER >= 0x10100000) {
            self::assertSame(2, (new ServerTlsContext)->getSecurityLevel());
        } else {
            self::assertSame(0, (new ServerTlsContext)->getSecurityLevel());
        }
    }

    public function testWithApplicationLayerProtocols(): void
    {
        if (!Socket\hasTlsAlpnSupport()) {
            self::markTestSkipped('OpenSSL 1.0.2 required');
        }

        $contextA = new ServerTlsContext;
        $contextB = $contextA->withApplicationLayerProtocols(['http/1.1', 'h2']);

        self::assertSame([], $contextA->getApplicationLayerProtocols());
        self::assertSame(['http/1.1', 'h2'], $contextB->getApplicationLayerProtocols());
    }

    public function testWithInvalidApplicationLayerProtocols(): void
    {
        if (!Socket\hasTlsAlpnSupport()) {
            self::markTestSkipped('OpenSSL 1.0.2 required');
        }

        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('Protocol names must be strings');

        $context = new ServerTlsContext;
        $context->withApplicationLayerProtocols([1, 2]);
    }
}
