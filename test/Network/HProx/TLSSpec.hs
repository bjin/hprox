-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.TLSSpec
  ( spec
  ) where

import Control.Exception     (ErrorCall, SomeException, displayException, fromException, try)
import Data.Maybe            (isNothing)
import Network.HProx.Config  (CertFile(..))
import Network.HProx.Runtime
import Network.TLS           qualified as TLS

import System.Directory (getTemporaryDirectory, removeFile)
import System.IO        (hClose, openTempFile)
import Test.Hspec

spec :: Spec
spec = do
  describe "SNI selection" $ do
    it "keeps the first configured certificate as the default certificate" $
      defaultCertificate certFixtures `shouldBe` Just "first-cert"

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

  describe "TLS credential loading" $
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

certFixtures :: [(String, String)]
certFixtures =
  [ ("first.example", "first-cert")
  , ("second.example", "second-cert")
  ]

missingPath :: String -> IO FilePath
missingPath template = do
  tmpDir <- getTemporaryDirectory
  (path, handle) <- openTempFile tmpDir template
  hClose handle
  removeFile path
  return path
