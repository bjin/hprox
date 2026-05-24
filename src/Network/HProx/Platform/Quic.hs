-- SPDX-License-Identifier: Apache-2.0

-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

{-# LANGUAGE CPP #-}

module Network.HProx.Platform.Quic
  ( runQuicAndTls
  ) where

import Network.TLS                 qualified as TLS
import Network.Wai                 (Application)
import Network.Wai.Handler.Warp    (Settings)
import Network.Wai.Handler.WarpTLS (TLSSettings, runTLS)

import Network.HProx.Log

#ifdef QUIC_ENABLED
import Control.Concurrent.Async     (mapConcurrently_)
import Data.ByteString.Char8        qualified as BS8
import Data.Default.Class           (def)
import Data.List                    (find)
import Data.Maybe                   (fromMaybe)
import Data.String                  (fromString)
import Network.QUIC.Internal        qualified as Q
import Network.Wai.Handler.Warp     (setAltSvc)
import Network.Wai.Handler.WarpQUIC (runQUIC)
#endif

runQuicAndTls
  :: Logger
  -> Maybe String
  -> Settings
  -> TLSSettings
  -> (Maybe String -> IO TLS.Credentials)
  -> TLS.SessionManager
  -> TLS.Credential
  -> Int
  -> Application
  -> IO ()
#ifdef QUIC_ENABLED
runQuicAndTls logger bind settings tlsSettings onSNI sessionManager defaultCert qport app = do
  logger INFO $ "bind to UDP port " <> toLogStr (fromMaybe "0.0.0.0" bind) <> ":" <> toLogStr qport
  mapConcurrently_ ($ app)
    [ runQUIC (quicSettings defaultCert qport) settings
    , runTLS tlsSettings (setAltSvc (altSvc qport) settings)
    ]
  where
    alpn _ = return . fromMaybe "" . find (== "h3")
    altSvc port = BS8.concat ["h3=\":", BS8.pack $ show port ,"\""]

    quicSettings cert port = Q.defaultServerConfig
      { Q.scAddresses      = [(fromString (fromMaybe "0.0.0.0" bind), fromIntegral port)]
      , Q.scVersions       = [Q.Version1, Q.Version2]
      , Q.scCredentials    = TLS.Credentials [cert]
      , Q.scALPN           = Just alpn
      , Q.scTlsHooks       = def { TLS.onServerNameIndication = onSNI }
      , Q.scUse0RTT        = True
      , Q.scSessionManager = sessionManager
      }
#else
runQuicAndTls _ _ settings tlsSettings _ _ _ _ app = runTLS tlsSettings settings app
#endif
