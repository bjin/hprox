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


#ifdef OS_UNIX
import Control.Exception    (SomeException, catch)
import System.Exit
import System.Posix.Process (exitImmediately)
import System.Posix.User
#endif

import Control.Monad

import Network.HProx.Auth
import Network.HProx.Config
import Network.HProx.Log
import Network.HProx.Runtime
import Paths_hprox


getLoggerType :: String -> LogType' LogStr
getLoggerType "none"   = LogNone
getLoggerType "stdout" = LogStdout 4096
getLoggerType "stderr" = LogStderr 4096
getLoggerType file     = LogFileNoRotate file 4096

#ifdef OS_UNIX
dropRootPriviledge :: Logger -> Maybe String -> Maybe String -> IO Bool
dropRootPriviledge _ Nothing Nothing = return False
dropRootPriviledge logger user group = do
    currentUser <- getRealUserID
    currentGroup <- getRealGroupID
    if currentUser /= 0 || currentGroup /= 0
      then do
        logger WARN $ "Unable to setuid/setgid without root priviledge" <>
                      ", userID=" <> toLogStr (show currentUser) <>
                      ", groupID=" <> toLogStr (show currentGroup)
        return False
      else do
        let abort msg = logger ERROR msg >> exitImmediately (ExitFailure 1)
        forM_ group $ \group' -> do
            logger INFO $ "setgid to " <> toLogStr group'
            getGroupEntryForName group' >>= setGroupID . groupID
            changedGroup <- getRealGroupID
            when (changedGroup == currentGroup) $ abort "failed to setgid, aborting"
        forM_ user $ \user' -> do
            logger INFO $ "setuid to " <> toLogStr user'
            getUserEntryForName user' >>= setUserID . userID
            changedUser <- getRealUserID
            when (changedUser == currentUser) $ abort "failed to setuid, aborting"
        logger DEBUG "testing setuid(0), verify that root priviledge can't be regranted"
        catch (setUserID 0) $ \(_ :: SomeException) -> logger DEBUG "setuid(0) failed as expected"
        changedUser <- getRealUserID
        when (changedUser == 0) $ abort "unable to drop root priviledge, aborting"
        return True
#endif


-- | Run HProx in front of fallback 'Application', with specified 'Config'
run :: Application -- ^ fallback application
    -> Config      -- ^ configuration
    -> IO ()
run fallback conf@Config{..} = withLogger (getLoggerType _log) _loglevel $ \logger -> do
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

    let proxyRuntime = buildProxyRuntime conf logger pauth isSSL
        pset = runtimeProxySettings proxyRuntime
        revSorted = runtimeReverseRoutes proxyRuntime
        proxy = buildProxyApplication isSSL pset manager fallback

    forM_ _ws $ \ws -> logger INFO $ "websocket redirect: " <> toLogStr ws
    unless (null revSorted) $ logger INFO $ "reverse proxy: " <> toLogStr (show revSorted)
    forM_ _doh $ \doh -> logger INFO $ "DNS-over-HTTPS redirect: " <> toLogStr doh

    runProxyServer conf logger settings smgr allCerts proxy
