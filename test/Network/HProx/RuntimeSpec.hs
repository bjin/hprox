-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

{-# LANGUAGE CPP #-}

module Network.HProx.RuntimeSpec
  ( spec
  ) where

import Control.Exception           (SomeException, displayException, toException)
import GHC.IO.Exception            (IOErrorType(..))
import Network.HTTP2.Client        qualified as H2
import Network.Wai
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS
import System.IO.Error             (mkIOError)

#ifdef QUIC_ENABLED
import Network.QUIC.Internal qualified as Q
#endif

import Network.HProx.Config
import Network.HProx.Log
import Network.HProx.Route
import Network.HProx.Runtime

import Test.Hspec

spec :: Spec
spec = do
  describe "RuntimeConfig" $
    it "normalizes log output and sorted reverse routes at the runtime boundary" $
      buildRuntimeConfig defaultConfig
        { _log = "stderr"
        , _rev =
            [ (Nothing, "/", "catch:80")
            , (Just "example.com", "/api/", "api:443")
            ]
        } `shouldBe` RuntimeConfig
          { runtimeConfigLogOutput = LogOutputStderr
          , runtimeConfigReverseRoutes =
              [ ReverseRoute (Just "example.com") "/api/" "api:443"
              , ReverseRoute Nothing "/" "catch:80"
              ]
          , runtimeConfigReverseRouteTuples =
              [ (Just "example.com", "/api/", "api:443")
              , (Nothing, "/", "catch:80")
              ]
          }
  describe "Warp runtime settings" $ do
    it "captures default bind, port, server name, and no-parse-path settings" $
      buildWarpRuntimePlan defaultConfig `shouldBe` WarpRuntimePlan
        { runtimeBindHost = "*6"
        , runtimePort = 3000
        , runtimeServerName = "hprox"
        , runtimeNoParsePath = True
        }

    it "captures configured bind, port, and server name settings" $
      buildWarpRuntimePlan defaultConfig
        { _bind = Just "127.0.0.1"
        , _port = 8080
        , _name = "custom"
        } `shouldBe` WarpRuntimePlan
          { runtimeBindHost = "127.0.0.1"
          , runtimePort = 8080
          , runtimeServerName = "custom"
          , runtimeNoParsePath = True
          }


  describe "runner selection" $ do
    it "selects the plain Warp runner when no certificates are configured" $
      selectRunnerPlan defaultConfig [] `shouldBe` PlainWarpRunner

    it "selects the TLS Warp runner when certificates are configured" $
      selectRunnerPlan defaultConfig [("example.com", ())] `shouldBe` TlsWarpRunner

#ifdef QUIC_ENABLED
    it "selects concurrent QUIC and TLS when QUIC is configured with certificates" $
      selectRunnerPlan defaultConfig { _quic = Just 443 } [("example.com", ())]
        `shouldBe` QuicAndTlsRunner 443

    it "does not select QUIC without configured certificates" $
      selectRunnerPlan defaultConfig { _quic = Just 443 } [] `shouldBe` PlainWarpRunner
#endif

  describe "DoH wrapping decision" $ do
    it "wraps the application only when a DoH resolver is configured" $ do
      shouldWrapDNSOverHTTPS defaultConfig `shouldBe` False
      shouldWrapDNSOverHTTPS defaultConfig { _doh = Just "127.0.0.1:53" } `shouldBe` True

  describe "startup side-effect order" $
    it "documents the current run startup order" $
      startupOrder `shouldBe`
        [ InitializeLogger
        , LogStartup
        , ReadCertificates
        , CreateTlsSessionManager
        , BuildSettingsAndRunner
        , LoadProxyAuth
        , CreateHttpManager
        , BuildProxyApplication
        , LogRuntimeConfig
        , StartRunner
        ]
  describe "access log filtering" $ do
    it "suppresses health-check access logs" $
      shouldSuppressAccessLog defaultRequest { rawPathInfo = "/.hprox/health" } `shouldBe` True

    it "keeps normal request access logs" $
      shouldSuppressAccessLog defaultRequest { rawPathInfo = "/" } `shouldBe` False

  describe "runtime exception filtering" $ do
    it "suppresses all exception logs above DEBUG level" $
      shouldIgnoreRuntimeException INFO displayedException `shouldBe` True

    it "keeps ordinary displayable exceptions at DEBUG level" $
      shouldIgnoreRuntimeException DEBUG displayedException `shouldBe` False

    it "unwraps HTTP/2 wrappers before selecting the exception to log" $
      fmap displayException (runtimeExceptionToLog DEBUG (toException (H2.BadThingHappen displayedException)))
        `shouldBe` Just (displayException displayedException)

    it "suppresses EOF IO exceptions" $
      shouldIgnoreRuntimeException DEBUG eofException `shouldBe` True

    it "suppresses HTTP/2 errors and recursively classified HTTP/2 wrappers" $ do
      shouldIgnoreRuntimeException DEBUG (toException H2.ConnectionIsClosed) `shouldBe` True
      shouldIgnoreRuntimeException DEBUG (toException (H2.BadThingHappen eofException)) `shouldBe` True

#ifdef QUIC_ENABLED
    it "suppresses QUIC errors and recursively classified QUIC wrappers" $ do
      shouldIgnoreRuntimeException DEBUG (toException Q.ConnectionIsReset) `shouldBe` True
      shouldIgnoreRuntimeException DEBUG (toException (Q.BadThingHappen eofException)) `shouldBe` True
#endif

    it "suppresses Warp TLS and peer-close exceptions" $ do
      shouldIgnoreRuntimeException DEBUG (toException InsecureConnectionDenied) `shouldBe` True
      shouldIgnoreRuntimeException DEBUG (toException ConnectionClosedByPeer) `shouldBe` True

displayedException :: SomeException
displayedException = toException $ userError "display me"

eofException :: SomeException
eofException = toException $ mkIOError EOF "eof" Nothing Nothing
