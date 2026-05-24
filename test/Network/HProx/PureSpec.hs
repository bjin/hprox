-- SPDX-License-Identifier: Apache-2.0

module Network.HProx.PureSpec
  ( spec
  ) where

import Data.List.NonEmpty qualified as NE

import Network.HProx.Log
import Network.HProx.Util

import Test.Hspec

spec :: Spec
spec = do
  describe "parseHostPort" $ do
    it "parses a valid host and port" $
      parseHostPort "example.com:443" `shouldBe` Just ("example.com", 443)

    it "uses the last colon as the port separator" $
      parseHostPort "example.com:proxy:8080" `shouldBe` Just ("example.com:proxy", 8080)

    it "accepts an empty host portion" $
      parseHostPort ":123" `shouldBe` Just ("", 123)

    it "rejects missing, invalid, trailing, and out-of-range ports" $
      map parseHostPort ["example.com", "example.com:http", "example.com:80x", "example.com:0", "example.com:65536", "example.com:"]
        `shouldBe` replicate 6 Nothing

  describe "parseHostPortWithDefault" $ do
    it "returns an explicit port when parsing succeeds" $
      parseHostPortWithDefault 80 "example.com:443" `shouldBe` ("example.com", 443)

    it "returns the original input and default port when parsing fails" $
      parseHostPortWithDefault 80 "example.com:not-a-port" `shouldBe` ("example.com:not-a-port", 80)

  describe "passwordReader" $ do
    it "parses plaintext password lines" $
      passwordReader "user:pass" `shouldBe` Just ("user", PlainText "pass")

    it "parses salted password lines by base64-decoding salt and hash" $
      passwordReader "user:c2FsdA==:aGFzaA==" `shouldBe` Just ("user", Salted "salt" "hash")

    it "rejects invalid salted and over-split password lines" $
      map passwordReader ["user:not-base64:also-not-base64", "user:pass:extra:field"]
        `shouldBe` [Nothing, Nothing]

  describe "passwordWriter" $
    it "writes salted password lines with base64 salt and hash" $
      passwordWriter "user" (PasswordSalted "salt" "hash") `shouldBe` "user:c2FsdA==:aGFzaA=="

  describe "logLevelReader" $ do
    it "parses all current log levels" $
      map logLevelReader ["trace", "debug", "info", "warn", "error", "none"]
        `shouldBe` map Just [TRACE, DEBUG, INFO, WARN, ERROR, NONE]

    it "rejects unknown log levels and different casing" $
      map logLevelReader ["", "warning", "INFO"] `shouldBe` replicate 3 Nothing

  describe "parseLogOutput" $
    it "preserves current log destination parsing policy" $
      map parseLogOutput ["none", "stdout", "stderr", "hprox.log"]
        `shouldBe` [LogOutputNone, LogOutputStdout, LogOutputStderr, LogOutputFile "hprox.log"]

  describe "splitBy" $ do
    it "preserves empty segments between, before, and after separators" $
      NE.toList (splitBy ':' ":a::b:") `shouldBe` ["", "a", "", "b", ""]

    it "returns one empty segment for empty input" $
      NE.toList (splitBy ':' "") `shouldBe` [""]
