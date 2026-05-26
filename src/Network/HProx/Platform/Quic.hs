-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

{-# LANGUAGE CPP #-}

module Network.HProx.Platform.Quic
  ( quicAddressPlan
  , quicAltSvc
#ifdef QUIC_ENABLED
  , buildQuicServerConfig
  , quicSessionManagerConfig
#endif
  , quicUse0RTT
  , runQuicAndTls
  ) where

import Data.ByteString.Char8       qualified as BS8
import Network.TLS                 qualified as TLS
import Network.Wai                 (Application)
import Network.Wai.Handler.Warp    (Settings)
import Network.Wai.Handler.WarpTLS (TLSSettings, runTLS)

import Network.HProx.Log

#ifdef QUIC_ENABLED
import Control.Concurrent.Async     (mapConcurrently_)
import Data.Default.Class           (def)
import Data.List                    (find)
import Data.Maybe                   (fromMaybe)
import Data.String                  (fromString)
import Network.QUIC.Internal        qualified as Q
import Network.TLS.SessionManager   qualified as SM
import Network.Wai.Handler.Warp     (setAltSvc)
import Network.Wai.Handler.WarpQUIC (runQUIC)
#endif

quicAltSvc :: Int -> BS8.ByteString
quicAltSvc port = BS8.concat ["h3=\":", BS8.pack $ show port, "\""]

quicAddressPlan :: Maybe String -> Int -> [(String, Int)]
-- Keep both wildcard sockets explicit: relying on an IPv6 wildcard socket
-- to receive IPv4 traffic depends on the host IPV6_V6ONLY default, while
-- QUIC creates one UDP socket per planned address and does not force that
-- socket option.
quicAddressPlan Nothing port     = [("0.0.0.0", port), ("::", port)]
quicAddressPlan (Just bind) port = [(bind, port)]

quicUse0RTT :: Bool
quicUse0RTT = False

runQuicAndTls
    :: Logger
    -> Maybe String
    -> Settings
    -> TLSSettings
    -> (Maybe String -> IO TLS.Credentials)
    -> Int
    -> Application
    -> IO ()
#ifdef QUIC_ENABLED
runQuicAndTls logger bind settings tlsSettings onSNI qport app = do
    logger INFO $ "bind to UDP port " <> toLogStr (fromMaybe "all interfaces" bind) <> ":" <> toLogStr qport
    sessionManager <- SM.newSessionManager quicSessionManagerConfig
    mapConcurrently_ ($ app)
        [ runQUIC (buildQuicServerConfig bind onSNI sessionManager qport) settings
        , runTLS tlsSettings (setAltSvc (quicAltSvc qport) settings)
        ]

alpn :: Q.Version -> [BS8.ByteString] -> IO BS8.ByteString
alpn _ protocols = return $ fromMaybe "" $ find (== "h3") protocols

buildQuicServerConfig
    :: Maybe String
    -> (Maybe String -> IO TLS.Credentials)
    -> TLS.SessionManager
    -> Int
    -> Q.ServerConfig
buildQuicServerConfig bind onSNI sessionManager port = Q.defaultServerConfig
    { Q.scAddresses      = [(fromString host, fromIntegral bindPort) | (host, bindPort) <- quicAddressPlan bind port]
    , Q.scVersions       = [Q.Version1, Q.Version2]
    , Q.scCredentials    = TLS.Credentials []
    , Q.scALPN           = Just alpn
    , Q.scTlsHooks       = def { TLS.onServerNameIndication = onSNI }
    , Q.scUse0RTT        = quicUse0RTT
    , Q.scSessionManager = sessionManager
    }

quicSessionManagerConfig :: SM.Config
quicSessionManagerConfig = SM.defaultConfig { SM.dbMaxSize = 0 }
#else
runQuicAndTls _ _ settings tlsSettings _ _ app = runTLS tlsSettings settings app
#endif
