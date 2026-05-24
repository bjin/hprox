-- SPDX-License-Identifier: Apache-2.0

-- Copyright (C) 2023 Bin Jin. All Rights Reserved.
{-# LANGUAGE CPP                 #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-| Instead of running @hprox@ binary directly, you can use this library
    to run HProx in front of arbitrary WAI 'Application'.
-}

module Network.HProx
  ( CertFile(..)
  , Config(..)
  , LogLevel(..)
  , defaultConfig
  , getConfig
  , run
  ) where

import Data.Version               (showVersion)
import Network.HTTP.Client.TLS    (newTlsManager)
import Network.TLS.SessionManager qualified as SM
import Network.Wai                (Application)



import Control.Monad

import Network.HProx.Auth
import Network.HProx.Config
import Network.HProx.Log
import Network.HProx.Platform.Unix
import Network.HProx.Runtime
import Paths_hprox





-- | Run HProx in front of fallback 'Application', with specified 'Config'
run :: Application -- ^ fallback application
    -> Config      -- ^ configuration
    -> IO ()
run fallback conf@Config{..} =
  let runtimeConfig = buildRuntimeConfig conf
  in withLogger (logOutputType (runtimeConfigLogOutput runtimeConfig)) _loglevel $ \logger -> do
    logger INFO $ "hprox " <> toLogStr (showVersion version) <> " started"

    allCerts <- loadTlsCredentials _ssl
    smgr <- SM.newSessionManager SM.defaultConfig

    let isSSL = not (null _ssl)

    when isSSL $ do
        logger INFO $ "read " <> toLogStr (show $ length allCerts) <> " certificates"
        logger INFO $ "domains: " <> toLogStr (unwords $ map fst allCerts)

    let beforeMainLoop =
#ifdef OS_UNIX
            Just doBeforeMainLoop
#else
            Nothing
#endif
        settings = buildWarpSettings conf logger beforeMainLoop

#ifdef OS_UNIX
        doBeforeMainLoop = do
            dropped <- dropRootPriviledge logger _user _group
#ifdef QUIC_ENABLED
            case (dropped, _quic) of
                (True, Just qport) | qport < 1024 -> logger ERROR $ "dropping root priviledge will likely break QUIC connection over UDP port " <> toLogStr (show qport)
                (True, _) -> logger INFO "root priviledge dropped"
                _ -> return ()
#else
            when dropped $ logger INFO "root priviledge dropped"
#endif
#endif


    pauth <- loadProxyAuth logger _auth

    manager <- newTlsManager

    let proxyRuntime = buildProxyRuntime runtimeConfig conf logger pauth isSSL
        pset = runtimeProxySettings proxyRuntime
        revSorted = runtimeReverseRoutes proxyRuntime
        proxy = buildProxyApplication isSSL pset manager fallback

    forM_ _ws $ \ws -> logger INFO $ "websocket redirect: " <> toLogStr ws
    unless (null revSorted) $ logger INFO $ "reverse proxy: " <> toLogStr (show revSorted)
    forM_ _doh $ \doh -> logger INFO $ "DNS-over-HTTPS redirect: " <> toLogStr doh

    runProxyServer conf logger settings smgr allCerts proxy
