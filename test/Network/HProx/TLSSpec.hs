-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.TLSSpec
  ( spec
  ) where

import Control.Exception
    (ErrorCall, SomeException, bracket, displayException, fromException, try)
import Crypto.Hash           qualified as Hash
import Data.ByteString       qualified as BS
import Data.ByteString.Char8 qualified as BS8
import Data.IORef            (modifyIORef', newIORef, readIORef)
import Data.List             (isInfixOf)
import Data.Maybe            (isNothing)
import Network.HProx.Config  (CertFile(..))
import Network.HProx.Log     (LogLevel(..), Logger)
import Network.HProx.Runtime
import Network.TLS           qualified as TLS

import System.Directory      (getTemporaryDirectory, removeFile)
import System.IO             (hClose, openTempFile)
import System.Log.FastLogger (fromLogStr)
import Test.Hspec

spec :: Spec
spec = do
    describe "SNI selection" $ do
        it "matches exact SNI hostnames case-insensitively" $ do
            lookupSNIHost (Just "EXAMPLE.com") [("example.com", "cert" :: String), ("other.example", "other")]
                `shouldBe` Right "cert"
            sniPatternMatches "EXAMPLE.com" "example.COM" `shouldBe` True
            sniPatternMatches "Ä.example.com" "ä.example.com" `shouldBe` False

        it "matches wildcard SNI hostnames case-insensitively for one label only" $ do
            sniPatternMatches "api.example.com" "*.example.com" `shouldBe` True
            sniPatternMatches "API.example.com" "*.EXAMPLE.com" `shouldBe` True
            sniPatternMatches "deep.api.example.com" "*.example.com" `shouldBe` False
            sniPatternMatches "example.com" "*.example.com" `shouldBe` False
            sniPatternMatches ".example.com" "*.example.com" `shouldBe` False
            sniPatternMatches "badexample.com" "*.example.com" `shouldBe` False

        it "returns the first matching configured SNI certificate" $
            lookupSNIHost (Just "api.example.com")
                [ ("*.example.com", "wildcard" :: String)
                , ("api.example.com", "exact")
                ] `shouldBe` Right "wildcard"

        it "rejects multi-label wildcard SNI matches during lookup" $
            lookupSNIHost (Just "deep.api.example.com") [("*.example.com", "wildcard" :: String)]
                `shouldBe` Left "SNI: unknown hostname (\"deep.api.example.com\")"

        it "rejects unknown and missing SNI hosts with current failure messages" $ do
            lookupSNIHost (Just "unknown.example") [("example.com", "cert" :: String)]
                `shouldBe` Left "SNI: unknown hostname (\"unknown.example\")"
            lookupSNIHost Nothing [("example.com", "cert" :: String)]
                `shouldBe` Left "SNI: unspecified"

    describe "TLS credential loading" $ do
        it "throws a contextual IO exception when certificate loading fails" $ do
            certPath <- missingPath "hprox-missing-cert.pem"
            keyPath <- missingPath "hprox-missing-key.pem"
            result <- try (loadTlsCredentials [("example.com", CertFile certPath keyPath)]) :: IO (Either SomeException [(String, TLS.Credential)])
            case result of
                Left ex -> do
                    fromException ex `shouldSatisfy` (isNothing :: Maybe ErrorCall -> Bool)
                    let message = displayException ex
                    message `shouldContain` "example.com"
                    message `shouldContain` certPath
                    message `shouldContain` keyPath
                Right _ -> expectationFailure "expected TLS credential loading to fail"

        it "rejects production credentials with an empty certificate chain" $
            loadTlsCredentialFromMemory "not a certificate" testPrivateKey
                `shouldBe` Left "loaded TLS credential has an empty certificate chain"

        it "keeps the old production credential when reload parses an empty certificate chain" $
            withTempCredential "hprox-valid" testCertificate testPrivateKey $ \certFile -> do
                store <- loadTlsCredentialStore [("example.com", certFile)]
                oldSnapshot <- readTlsCredentialStore store
                writeCredentialFiles certFile "not a certificate" testPrivateKey
                (logger, readLogs) <- captureLogger
                reloadTlsCredentialStore logger store
                readTlsCredentialStore store `shouldReturn` oldSnapshot
                logs <- readLogs
                let errorMessages = [message | (ERROR, message) <- logs]
                length errorMessages `shouldBe` 1
                unlines errorMessages `shouldContain` "example.com"
                unlines errorMessages `shouldContain` certfile certFile
                unlines errorMessages `shouldContain` keyfile certFile
                unlines errorMessages `shouldContain` "empty certificate chain"

    describe "reloadable TLS credential store" $ do
        it "looks up SNI credentials from the current store snapshot" $
            withTempCredential "hprox-store" "cert-a" "key-a" $ \certFile -> do
                store <- newTlsCredentialStore testCredentialLoader [("example.com", certFile)]
                lookupTlsCredentialStore (Just "example.com") store `shouldReturn` "cert-a:key-a"
                writeCredentialFiles certFile "cert-b" "key-b"
                (logger, _) <- captureLogger
                reloadTlsCredentialStore logger store
                lookupTlsCredentialStore (Just "example.com") store `shouldReturn` "cert-b:key-b"

        it "selects the current first configured credential for missing SNI" $
            withTempCredential "hprox-first" "first-cert" "first-key" $ \firstCert ->
            withTempCredential "hprox-second" "second-cert" "second-key" $ \secondCert -> do
                store <- newTlsCredentialStore testCredentialLoader
                    [ ("first.example", firstCert)
                    , ("second.example", secondCert)
                    ]
                lookupTlsCredentialStore Nothing store `shouldReturn` "first-cert:first-key"
                writeCredentialFiles firstCert "new-first-cert" "new-first-key"
                (logger, _) <- captureLogger
                reloadTlsCredentialStore logger store
                lookupTlsCredentialStore Nothing store `shouldReturn` "new-first-cert:new-first-key"

        it "logs an install message only for changed credentials" $
            withTempCredential "hprox-first" "first-cert" "first-key" $ \firstCert ->
            withTempCredential "hprox-second" "second-cert" "second-key" $ \secondCert -> do
                store <- newTlsCredentialStore testCredentialLoader
                    [ ("first.example", firstCert)
                    , ("second.example", secondCert)
                    ]
                writeCredentialFiles firstCert "new-first-cert" "new-first-key"
                (logger, readLogs) <- captureLogger
                reloadTlsCredentialStore logger store
                readTlsCredentialStore store `shouldReturn`
                    [ ("first.example", "new-first-cert:new-first-key")
                    , ("second.example", "second-cert:second-key")
                    ]
                logs <- readLogs
                let installMessages = [message | (INFO, message) <- logs, "installed reloaded TLS credential" `isInfixOf` message]
                length installMessages `shouldBe` 1
                unlines installMessages `shouldContain` "first.example"
                unlines installMessages `shouldContain` certfile firstCert
                unlines installMessages `shouldNotSatisfy` isInfixOf (certfile secondCert)

        it "keeps a failed entry, updates successful entries, and logs failure context" $
            withTempCredential "hprox-first" "first-cert" "first-key" $ \firstCert ->
            withTempCredential "hprox-second" "second-cert" "second-key" $ \secondCert -> do
                store <- newTlsCredentialStore failingCredentialLoader
                    [ ("first.example", firstCert)
                    , ("second.example", secondCert)
                    ]
                writeCredentialFiles firstCert "bad-cert" "first-key"
                writeCredentialFiles secondCert "new-second-cert" "new-second-key"
                (logger, readLogs) <- captureLogger
                reloadTlsCredentialStore logger store
                readTlsCredentialStore store `shouldReturn`
                    [ ("first.example", "first-cert:first-key")
                    , ("second.example", "new-second-cert:new-second-key")
                    ]
                logs <- readLogs
                let errorMessages = [message | (ERROR, message) <- logs]
                length errorMessages `shouldBe` 1
                unlines errorMessages `shouldContain` "first.example"
                unlines errorMessages `shouldContain` certfile firstCert
                unlines errorMessages `shouldContain` keyfile firstCert
                unlines errorMessages `shouldContain` "bad test credential"

missingPath :: String -> IO FilePath
missingPath template = do
    tmpDir <- getTemporaryDirectory
    (path, handle) <- openTempFile tmpDir template
    hClose handle
    removeFile path
    return path

type CapturedLogs = [(LogLevel, String)]

captureLogger :: IO (Logger, IO CapturedLogs)
captureLogger = do
    ref <- newIORef []
    let logger level message =
            modifyIORef' ref (++ [(level, BS8.unpack $ fromLogStr message)])
    return (logger, readIORef ref)

testCredentialLoader :: TlsCredentialLoader String
testCredentialLoader certFile = do
    certBytes <- BS.readFile $ certfile certFile
    keyBytes <- BS.readFile $ keyfile certFile
    return $ Right LoadedCredential
        { loadedCredentialValue = credentialValue certBytes keyBytes
        , loadedCredentialCertificateFingerprint = fingerprintBytes certBytes
        , loadedCredentialKeyFingerprint = fingerprintBytes keyBytes
        }

failingCredentialLoader :: TlsCredentialLoader String
failingCredentialLoader certFile = do
    certBytes <- BS.readFile $ certfile certFile
    keyBytes <- BS.readFile $ keyfile certFile
    if certBytes == "bad-cert"
        then return $ Left "bad test credential"
        else return $ Right LoadedCredential
            { loadedCredentialValue = credentialValue certBytes keyBytes
            , loadedCredentialCertificateFingerprint = fingerprintBytes certBytes
            , loadedCredentialKeyFingerprint = fingerprintBytes keyBytes
            }

credentialValue :: BS.ByteString -> BS.ByteString -> String
credentialValue certBytes keyBytes =
    BS8.unpack certBytes <> ":" <> BS8.unpack keyBytes

fingerprintBytes :: BS.ByteString -> Hash.Digest Hash.SHA256
fingerprintBytes = Hash.hash

withTempCredential :: String -> BS.ByteString -> BS.ByteString -> (CertFile -> IO a) -> IO a
withTempCredential template certBytes keyBytes =
    bracket acquire release
  where
    acquire = do
        tmpDir <- getTemporaryDirectory
        (certPath, certHandle) <- openTempFile tmpDir $ template <> "-cert.pem"
        (keyPath, keyHandle) <- openTempFile tmpDir $ template <> "-key.pem"
        hClose certHandle
        hClose keyHandle
        let certFile = CertFile certPath keyPath
        writeCredentialFiles certFile certBytes keyBytes
        return certFile

    release (CertFile certPath keyPath) = do
        removeFile certPath
        removeFile keyPath

writeCredentialFiles :: CertFile -> BS.ByteString -> BS.ByteString -> IO ()
writeCredentialFiles (CertFile certPath keyPath) certBytes keyBytes = do
    BS.writeFile certPath certBytes
    BS.writeFile keyPath keyBytes

testPrivateKey :: BS.ByteString
testPrivateKey = BS8.pack $
    "-----BEGIN PRIVATE KEY-----\n" <>
    "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAOWBh4304R0FzpHZ\n" <>
    "PltVBN0lZ3WRqF/ETDhtqR071G/d7lkikLu0QXP7pCaDK4rHcHSm3TmE1Flcyc94\n" <>
    "wfFIVJinXEiJd+bp1Yk/ZWkWTYMEX5OuYzWBhciULt+ekMz8I2W+gtFUyu5rL9M9\n" <>
    "DaNPwQijTxYaykBJ4uXzUjxm7NwhAgMBAAECgYB6ndeUak6TOPUCSzTbivLMTB2Y\n" <>
    "XLe+YpvuUfhWXA7FraaYDLWS81084Cb1RINQ4/ka+cOb5XGmRMK1i+jiRiibWw38\n" <>
    "R/j0xZhsHSaGSuFlP189O+eA00q34vw0cvKxl1OJGcRF8/lq4qrpgh63iAM+EAC/\n" <>
    "9ncMbpkQrmfluuuOAQJBAP6TLeVAnKnj4i0MtuN1xhofZ3Kdr2Ds1cbHxpeT/yE1\n" <>
    "Q8HZEIynoFVfTZe2fJs0V6YlLlv4lJhfIXy/EixrmvECQQDmymzKz5hJhxlWNLLy\n" <>
    "3t92gh3o03u5ijM7c+HVLJZVI4Co2ai9f0aRifOWKRAbmth5zUVDcJG53jMaQeQQ\n" <>
    "D3QxAkEAyR0AvwHCQjyza5+FxEBAllaE5PlJmarAX99nNkxG27c2pieTeWrbsVYu\n" <>
    "+FHEMuCw9aKd8y54Rb+xttlDxC/mIQJBAMLuUrlyYhQokdPoKwVMDb6Q5CZVCfmK\n" <>
    "qv8aP7LIOCmtFOyI+ycjKz2eISnBgSNvxEwMfuYZXFx7OvqAkNqn0uECQQC59Uk/\n" <>
    "yEl0AkTKP2tcn55afpArQfPdZbIns6koiAMpoyxJPTsB2wL9b77Z8cNfgknFQVpP\n" <>
    "vpX74UfeEF0AYB7t\n" <>
    "-----END PRIVATE KEY-----\n"

testCertificate :: BS.ByteString
testCertificate = BS8.pack $
    "-----BEGIN CERTIFICATE-----\n" <>
    "MIICCDCCAXGgAwIBAgIUdG9y2ED6kiMvkMveoyy1uxRoeIUwDQYJKoZIhvcNAQEL\n" <>
    "BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjYwNTI2MTUzMzQyWhcNMjYw\n" <>
    "NTI3MTUzMzQyWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0B\n" <>
    "AQEFAAOBjQAwgYkCgYEA5YGHjfThHQXOkdk+W1UE3SVndZGoX8RMOG2pHTvUb93u\n" <>
    "WSKQu7RBc/ukJoMrisdwdKbdOYTUWVzJz3jB8UhUmKdcSIl35unViT9laRZNgwRf\n" <>
    "k65jNYGFyJQu356QzPwjZb6C0VTK7msv0z0No0/BCKNPFhrKQEni5fNSPGbs3CEC\n" <>
    "AwEAAaNTMFEwHQYDVR0OBBYEFIVxo9w8xVcdjoMDWXAc45756MAsMB8GA1UdIwQY\n" <>
    "MBaAFIVxo9w8xVcdjoMDWXAc45756MAsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI\n" <>
    "hvcNAQELBQADgYEApCff6vbA5sIRVjRuxSj0Lw37RI6Qb8vaXDELxIrmXVL4b3al\n" <>
    "fLV9eJ54Lmv5mws+mziC2Nohvh6nW343oRip85u8OfalLi5enxq7FnWoXeOPVUmr\n" <>
    "8DnHkJjatk0TVsvV6JLHeJDzX/Pqw4G8JrBYbQVgOqsfWw6bk2vkrHzYOgA=\n" <>
    "-----END CERTIFICATE-----\n"
