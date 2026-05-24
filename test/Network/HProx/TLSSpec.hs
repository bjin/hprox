-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.TLSSpec
  ( spec
  ) where

import Network.HProx.Runtime

import Test.Hspec

spec :: Spec
spec =
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

certFixtures :: [(String, String)]
certFixtures =
  [ ("first.example", "first-cert")
  , ("second.example", "second-cert")
  ]
