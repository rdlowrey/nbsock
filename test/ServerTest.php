<?php

namespace Amp\Socket\Test;

use Amp\CancelledException;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Socket;
use Amp\Socket\Server;
use Amp\TimeoutCancellation;
use Revolt\EventLoop;
use function Amp\delay;
use function Amp\ByteStream\buffer;
use function Amp\async;

class ServerTest extends AsyncTestCase
{
    public function testListenInvalidScheme(): void
    {
        $this->expectException(\Error::class);
        $this->expectExceptionMessage('Only tcp and unix schemes allowed for server creation');

        Server::listen("invalid://127.0.0.1:0");
    }

    public function testListenStreamSocketServerError(): void
    {
        $this->expectException(Socket\SocketException::class);
        $this->expectExceptionMessageMatches('/Could not create server .*: \[Error: #.*\] .*$/');

        Server::listen('error');
    }

    public function testListenIPv6(): void
    {
        try {
            $socket = Server::listen('[::1]:0');
            self::assertMatchesRegularExpression('(\[::1\]:\d+)', (string) $socket->getAddress());
        } catch (Socket\SocketException $e) {
            if ($e->getMessage() === 'Could not create server tcp://[::1]:0: [Error: #0] Cannot assign requested address') {
                self::markTestSkipped('Missing IPv6 support');
            }

            throw $e;
        }
    }

    public function testAccept(): void
    {
        $server = Server::listen('127.0.0.1:0');

        EventLoop::queue(function () use ($server): void {
            while ($socket = $server->accept()) {
                $this->assertInstanceOf(Socket\ResourceSocket::class, $socket);
            }
        });

        $socket = Socket\connect($server->getAddress());

        delay(0.001);

        $socket->close();
        $server->close();
    }

    public function testTls(): void
    {
        $tlsContext = (new Socket\ServerTlsContext)
            ->withDefaultCertificate(new Socket\Certificate(__DIR__ . '/tls/amphp.org.pem'));
        $server = Server::listen('127.0.0.1:0', (new Socket\BindContext)->withTlsContext($tlsContext));

        EventLoop::queue(function () use ($server): void {
            while ($socket = $server->accept()) {
                EventLoop::queue(function () use ($socket): void {
                    $socket->setupTls();
                    $this->assertInstanceOf(Socket\ResourceSocket::class, $socket);
                    $this->assertSame('Hello World', $socket->read());
                    $socket->write('test')->await();
                    $socket->close();
                });
            }
        });

        $context = (new Socket\ConnectContext)->withTlsContext(
            (new Socket\ClientTlsContext('amphp.org'))
                ->withCaFile(__DIR__ . '/tls/amphp.org.crt')
        );

        try {
            $client = Socket\connect($server->getAddress(), $context);
            $client->setupTls();
            $client->write('Hello World')->await();

            self::assertSame('test', buffer($client));
        } finally {
            $server->close();
        }
    }

    public function testSniWorksWithCorrectHostName(): void
    {
        $tlsContext = (new Socket\ServerTlsContext)
            ->withCertificates(['amphp.org' => new Socket\Certificate(__DIR__ . '/tls/amphp.org.pem')]);
        $server = Server::listen('127.0.0.1:0', (new Socket\BindContext)->withTlsContext($tlsContext));

        EventLoop::queue(function () use ($server): void {
            /** @var Socket\EncryptableSocket $socket */
            while ($socket = $server->accept()) {
                EventLoop::queue(function () use ($socket): void {
                    $socket->setupTls();
                    $this->assertInstanceOf(Socket\ResourceSocket::class, $socket);
                    $this->assertSame('Hello World', $socket->read());
                    $socket->write('test')->await();
                });
            }
        });

        $context = (new Socket\ConnectContext)->withTlsContext(
            (new Socket\ClientTlsContext('amphp.org'))
                ->withCaFile(__DIR__ . '/tls/amphp.org.crt')
        );

        try {
            $client = Socket\connect($server->getAddress(), $context);
            $client->setupTls();
            $client->write('Hello World')->await();

            self::assertSame('test', $client->read());
        } finally {
            $server->close();
        }
    }

    public function testSniWorksWithMultipleCertificates(): void
    {
        $tlsContext = (new Socket\ServerTlsContext)->withCertificates([
            'amphp.org' => new Socket\Certificate(__DIR__ . '/tls/amphp.org.pem'),
            'www.amphp.org' => new Socket\Certificate(__DIR__ . '/tls/www.amphp.org.pem'),
        ]);

        $server = Server::listen('127.0.0.1:0', (new Socket\BindContext)->withTlsContext($tlsContext));

        EventLoop::queue(function () use ($server): void {
            /** @var Socket\ResourceSocket $socket */
            while ($socket = $server->accept()) {
                EventLoop::queue(function () use ($socket): void {
                    $socket->setupTls();
                    $this->assertInstanceOf(Socket\ResourceSocket::class, $socket);
                    $this->assertSame('Hello World', $socket->read());
                    $socket->write('test')->await();
                });
            }
        });

        try {
            $context = (new Socket\ConnectContext)->withTlsContext(
                (new Socket\ClientTlsContext('amphp.org'))
                    ->withCaFile(__DIR__ . '/tls/amphp.org.crt')
            );

            $client = Socket\connect($server->getAddress(), $context);
            $client->setupTls();
            $client->write('Hello World')->await();
            self::assertSame('test', $client->read());

            $context = (new Socket\ConnectContext)->withTlsContext(
                (new Socket\ClientTlsContext('www.amphp.org'))
                    ->withCaFile(__DIR__ . '/tls/www.amphp.org.crt')
            );

            $client = Socket\connect($server->getAddress(), $context);
            $client->setupTls();
            $client->write('Hello World')->await();
            self::assertSame('test', $client->read());
        } finally {
            $server->close();
        }
    }

    public function testSniWorksWithMultipleCertificatesAndDifferentFilesForCertAndKey(): void
    {
        $tlsContext = (new Socket\ServerTlsContext)->withCertificates([
            'amphp.org' => new Socket\Certificate(__DIR__ . '/tls/amphp.org.crt', __DIR__ . '/tls/amphp.org.key'),
            'www.amphp.org' => new Socket\Certificate(
                __DIR__ . '/tls/www.amphp.org.crt',
                __DIR__ . '/tls/www.amphp.org.key'
            ),
        ]);

        $server = Server::listen('127.0.0.1:0', (new Socket\BindContext)->withTlsContext($tlsContext));

        EventLoop::queue(function () use ($server): void {
            /** @var Socket\ResourceSocket $socket */
            while ($socket = $server->accept()) {
                EventLoop::queue(function () use ($socket): void {
                    $socket->setupTls();
                    $this->assertInstanceOf(Socket\ResourceSocket::class, $socket);
                    $this->assertSame('Hello World', $socket->read());
                    $socket->write('test')->await();
                });
            }
        });

        try {
            $context = (new Socket\ConnectContext)->withTlsContext(
                (new Socket\ClientTlsContext('amphp.org'))
                    ->withCaFile(__DIR__ . '/tls/amphp.org.crt')
            );

            $client = Socket\connect($server->getAddress(), $context);
            $client->setupTls();
            $client->write('Hello World')->await();
            self::assertSame('test', $client->read());

            $context = (new Socket\ConnectContext)->withTlsContext(
                (new Socket\ClientTlsContext('www.amphp.org'))
                    ->withCaFile(__DIR__ . '/tls/www.amphp.org.crt')
            );

            $client = Socket\connect($server->getAddress(), $context);
            $client->setupTls();
            $client->write('Hello World')->await();
            self::assertSame('test', $client->read());
        } finally {
            $server->close();
        }
    }

    public function testCancelThenAccept(): void
    {
        $server = Server::listen('127.0.0.1:0');

        try {
            $server->accept(new TimeoutCancellation(0.01));
            $this->fail('The accept should have been cancelled');
        } catch (CancelledException) {
        }

        $future = async(fn () => Socket\connect($server->getAddress()));

        $serverSocket = $server->accept();
        $clientSocket = $future->await();

        $data = 'test';
        $serverSocket->write($data)->ignore();
        self::assertSame($data, $clientSocket->read());
    }
}
