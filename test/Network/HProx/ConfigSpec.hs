-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.
{-# LANGUAGE CPP #-}

module Network.HProx.ConfigSpec
  ( spec
  ) where

import Control.Exception  (try)
import System.Environment (withArgs)
import System.Exit        (ExitCode(..))

import Network.HProx

import Test.Hspec

spec :: Spec
spec = do
  describe "defaultConfig" $
    it "matches the documented default runtime values" $
      assertDefaultConfig defaultConfig

  describe "getConfig" $ do
    it "uses default configuration when no options are supplied" $ do
      conf <- parseConfig []
      assertDefaultConfig conf

    it "parses long-form options into the current Config fields" $ do
      conf <- parseConfig longOptionArgs
      _bind conf `shouldBe` Just "127.0.0.1"
      _port conf `shouldBe` 8080
      case _ssl conf of
        [(host, cert)] -> do
          host `shouldBe` "example.com"
          certfile cert `shouldBe` "cert.pem"
          keyfile cert `shouldBe` "key.pem"
        value -> expectationFailure $ "unexpected TLS entries: " <> show (length value)
      _auth conf `shouldBe` Just "userpass.txt"
      _ws conf `shouldBe` Just "ws.example:443"
      _rev conf `shouldBe` [(Just "example.com", "/api/", "upstream:80")]
      _doh conf `shouldBe` Just "1.1.1.1:53"
      _hide conf `shouldBe` True
      _naive conf `shouldBe` True
      _name conf `shouldBe` "custom"
      _acme conf `shouldBe` Just "thumbprint"
      _log conf `shouldBe` "stderr"
      _loglevel conf `shouldBe` DEBUG
#ifdef OS_UNIX
      _user conf `shouldBe` Just "nobody"
      _group conf `shouldBe` Just "nogroup"
#endif
#ifdef QUIC_ENABLED
      _quic conf `shouldBe` Just 8443
#endif

    it "parses current short aliases" $ do
      conf <- parseConfig shortOptionArgs
      _bind conf `shouldBe` Just "0.0.0.0"
      _port conf `shouldBe` 8081
      case _ssl conf of
        [(host, cert)] -> do
          host `shouldBe` "short.example"
          certfile cert `shouldBe` "short-cert.pem"
          keyfile cert `shouldBe` "short-key.pem"
        value -> expectationFailure $ "unexpected TLS entries: " <> show (length value)
      _auth conf `shouldBe` Just "short-userpass.txt"
#ifdef OS_UNIX
      _user conf `shouldBe` Just "daemon"
      _group conf `shouldBe` Just "daemon"
#endif
#ifdef QUIC_ENABLED
      _quic conf `shouldBe` Just 9443
#endif

    it "parses reverse proxy option forms" $ do
      remoteOnly <- parseConfig ["--rev", "backend:80"]
      prefixOnly <- parseConfig ["--rev", "/api/backend:80"]
      domainAndPrefix <- parseConfig ["--rev", "//example.com/api/backend:80"]
      _rev remoteOnly `shouldBe` [(Nothing, "/", "backend:80")]
      _rev prefixOnly `shouldBe` [(Nothing, "/api/", "backend:80")]
      _rev domainAndPrefix `shouldBe` [(Just "example.com", "/api/", "backend:80")]

    it "accepts only bounded listener ports" $ do
      low <- parseConfig ["--port", "1"]
      high <- parseConfig ["--port", "65535"]
      _port low `shouldBe` 1
      _port high `shouldBe` 65535
      shouldExitWith ["--port", "0"] (ExitFailure 1)
      shouldExitWith ["--port", "65536"] (ExitFailure 1)
      shouldExitWith ["--port", "-1"] (ExitFailure 1)

#ifdef QUIC_ENABLED
    it "accepts only bounded QUIC ports" $ do
      low <- parseConfig ["--quic", "1"]
      high <- parseConfig ["--quic", "65535"]
      _quic low `shouldBe` Just 1
      _quic high `shouldBe` Just 65535
      shouldExitWith ["--quic", "0"] (ExitFailure 1)
      shouldExitWith ["--quic", "65536"] (ExitFailure 1)
      shouldExitWith ["--quic", "-1"] (ExitFailure 1)
#endif
    it "rejects invalid TLS, reverse proxy, and log-level options" $ do
      shouldExitWith ["--tls", "example.com:cert-only"] (ExitFailure 1)
      shouldExitWith ["--rev", "//example.com"] (ExitFailure 1)
      shouldExitWith ["--rev", "/api/"] (ExitFailure 1)
      shouldExitWith ["--rev", "/"] (ExitFailure 1)
      shouldExitWith ["--rev", "///api/backend:80"] (ExitFailure 1)
      shouldExitWith ["--loglevel", "verbose"] (ExitFailure 1)

    it "exercises help and version parser exits" $ do
      shouldExitWith ["--help"] ExitSuccess
      shouldExitWith ["--version"] ExitSuccess

assertDefaultConfig :: Config -> Expectation
assertDefaultConfig conf = do
  _bind conf `shouldBe` Nothing
  _port conf `shouldBe` 3000
  length (_ssl conf) `shouldBe` 0
  _auth conf `shouldBe` Nothing
  _ws conf `shouldBe` Nothing
  _rev conf `shouldBe` []
  _doh conf `shouldBe` Nothing
  _hide conf `shouldBe` False
  _naive conf `shouldBe` False
  _name conf `shouldBe` "hprox"
  _acme conf `shouldBe` Nothing
  _log conf `shouldBe` "stdout"
  _loglevel conf `shouldBe` INFO
#ifdef OS_UNIX
  _user conf `shouldBe` Nothing
  _group conf `shouldBe` Nothing
#endif
#ifdef QUIC_ENABLED
  _quic conf `shouldBe` Nothing
#endif

parseConfig :: [String] -> IO Config
parseConfig args = withArgs args getConfig

shouldExitWith :: [String] -> ExitCode -> Expectation
shouldExitWith args expected = do
  result <- try (parseConfig args)
  case result of
    Left exitCode -> exitCode `shouldBe` expected
    Right _       -> expectationFailure "expected parser to exit"

longOptionArgs :: [String]
longOptionArgs =
  [ "--bind", "127.0.0.1"
  , "--port", "8080"
  , "--tls", "example.com:cert.pem:key.pem"
  , "--auth", "userpass.txt"
  , "--ws", "ws.example:443"
  , "--rev", "//example.com/api/upstream:80"
  , "--doh", "1.1.1.1:53"
  , "--hide"
  , "--naive"
  , "--name", "custom"
  , "--acme", "thumbprint"
  , "--log", "stderr"
  , "--loglevel", "debug"
#ifdef OS_UNIX
  , "--user", "nobody"
  , "--group", "nogroup"
#endif
#ifdef QUIC_ENABLED
  , "--quic", "8443"
#endif
  ]

shortOptionArgs :: [String]
shortOptionArgs =
  [ "-b", "0.0.0.0"
  , "-p", "8081"
  , "-s", "short.example:short-cert.pem:short-key.pem"
  , "-a", "short-userpass.txt"
#ifdef OS_UNIX
  , "-u", "daemon"
  , "-g", "daemon"
#endif
#ifdef QUIC_ENABLED
  , "-q", "9443"
#endif
  ]
