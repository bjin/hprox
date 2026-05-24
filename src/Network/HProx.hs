-- SPDX-License-Identifier: Apache-2.0

-- Copyright (C) 2023 Bin Jin. All Rights Reserved.
{-# LANGUAGE CPP                 #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns        #-}

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

#ifdef QUIC_ENABLED
import Data.ByteString.Char8 qualified as BS8
import Data.Default.Class    (def)
#endif
import Data.String             (fromString)
import Data.Version            (showVersion)
import Network.HTTP.Client.TLS (newTlsManager)
import Network.HTTP.Types      qualified as HT
#ifdef QUIC_ENABLED
import Network.TLS qualified as TLS
#endif
import Network.TLS.SessionManager  qualified as SM
import Network.Wai                 (Application, rawPathInfo)
import Network.Wai.Handler.Warp
    (InvalidRequest(..), defaultSettings, defaultShouldDisplayException, runSettings, setHost,
    setLogger, setNoParsePath, setOnException, setPort, setServerName)
import Network.Wai.Handler.WarpTLS (WarpTLSException, runTLS)

import Control.Exception    (Exception(..))
import GHC.IO.Exception     (IOErrorType(..))
import Network.HTTP2.Client qualified as H2
import System.IO.Error      (ioeGetErrorType)

#ifdef QUIC_ENABLED
import Control.Concurrent.Async     (mapConcurrently_)
import Data.List                    (find)
import Network.QUIC                 qualified as Q
import Network.QUIC.Internal        qualified as Q
import Network.Wai.Handler.Warp     (setAltSvc)
import Network.Wai.Handler.WarpQUIC (runQUIC)
#endif

#ifdef OS_UNIX
import Control.Exception        (SomeException, catch)
import Network.Wai.Handler.Warp (setBeforeMainLoop)
import System.Exit
import System.Posix.Process     (exitImmediately)
import System.Posix.User
#endif

import Control.Monad
import Data.Maybe

import Network.HProx.Auth
import Network.HProx.Config
import Network.HProx.DoH
import Network.HProx.Impl
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

    let settings = setHost (fromString (fromMaybe "*6" _bind)) $
                   setPort _port $
                   setLogger warpLogger $
                   setOnException exceptionHandler $
#ifdef OS_UNIX
                   setBeforeMainLoop doBeforeMainLoop $
#endif
                   setNoParsePath True $
                   setServerName _name defaultSettings

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

        exceptionHandler req ex
            | _loglevel > DEBUG                                 = return ()
            | not (defaultShouldDisplayException ex)            = return ()
            | Just (ioeGetErrorType -> EOF) <- fromException ex = return ()
            | Just (H2.BadThingHappen ex') <- fromException ex  = exceptionHandler req ex'
            | Just (_ :: H2.HTTP2Error) <- fromException ex     = return ()
#ifdef QUIC_ENABLED
            | Just (Q.BadThingHappen ex') <- fromException ex   = exceptionHandler req ex'
            | Just (_ :: Q.QUICException) <- fromException ex   = return ()
#endif
            | Just (_ :: WarpTLSException) <- fromException ex  = return ()
            | Just ConnectionClosedByPeer <- fromException ex   = return ()
            | otherwise                                         =
                logger DEBUG $ "exception: " <> toLogStr (displayException ex) <>
                    maybe "" (\req' -> " from: " <> logRequest req') req

        warpLogger req status _
            | rawPathInfo req == "/.hprox/health" = return ()
            | otherwise                           =
                logger TRACE $ "(" <> toLogStr (HT.statusCode status) <> ") " <> logRequest req

#ifdef QUIC_ENABLED
        alpn _ = return . fromMaybe "" . find (== "h3")
        altsvc qport = BS8.concat ["h3=\":", BS8.pack $ show qport ,"\""]

        quicset defaultCert qport = Q.defaultServerConfig
            { Q.scAddresses      = [(fromString (fromMaybe "0.0.0.0" _bind), fromIntegral qport)]
            , Q.scVersions       = [Q.Version1, Q.Version2]
            , Q.scCredentials    = TLS.Credentials [defaultCert]
            , Q.scALPN           = Just alpn
            , Q.scTlsHooks       = def { TLS.onServerNameIndication = lookupSNICredentials' }
            , Q.scUse0RTT        = True
            , Q.scSessionManager = smgr
            }

        lookupSNICredentials' host = lookupSNICredentials host allCerts

        runner = case allCerts of
            []                  -> runSettings settings
            (_, defaultCert) : _ | Just qport <- _quic -> \app -> do
                logger INFO $ "bind to UDP port " <> toLogStr (fromMaybe "0.0.0.0" _bind) <> ":" <> toLogStr qport
                mapConcurrently_ ($ app)
                    [ runQUIC (quicset defaultCert qport) settings
                    , runTLS (buildTlsSettings smgr allCerts defaultCert) (setAltSvc (altsvc qport) settings)
                    ]
            (_, defaultCert) : _ -> runTLS (buildTlsSettings smgr allCerts defaultCert) settings
#else
        runner = case allCerts of
            []                   -> runSettings settings
            (_, defaultCert) : _ -> runTLS (buildTlsSettings smgr allCerts defaultCert) settings
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

    logger INFO $ "bind to TCP port " <> toLogStr (fromMaybe "[::]" _bind) <> ":" <> toLogStr _port
    case _doh of
        Nothing  -> runner proxy
        Just doh -> createResolver doh (\resolver -> runner (dnsOverHTTPS resolver proxy))
