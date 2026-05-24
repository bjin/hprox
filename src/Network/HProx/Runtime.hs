-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

{-# LANGUAGE CPP                 #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.HProx.Runtime
  ( ProxyRuntime(..)
  , RunnerPlan(..)
  , RuntimeConfig(..)
  , StartupStep(..)
  , WarpRuntimePlan(..)
  , buildProxyApplication
  , buildProxyRuntime
  , buildRuntimeConfig
  , buildTlsSettings
  , buildWarpRuntimePlan
  , buildWarpSettings
  , defaultCertificate
  , loadTlsCredentials
  , lookupSNICredentials
  , lookupSNIHost
  , runProxyServer
  , runtimeExceptionToLog
  , selectRunnerPlan
  , shouldIgnoreRuntimeException
  , shouldSuppressAccessLog
  , shouldWrapDNSOverHTTPS
  , sniPatternMatches
  , startupOrder
  , validateRuntimeConfig
  ) where

import Control.Exception
    (IOException, SomeException, displayException, fromException, try)
import Data.ByteString.Char8       qualified as BS8
import Data.Default.Class          (def)
import Data.List                   (sortOn)
import Data.Maybe                  (fromMaybe, isJust, isNothing)
import Data.Ord                    (Down(..))
import Data.String                 (fromString)
import GHC.IO.Exception            (IOErrorType(..))
import Network.HTTP.Client         qualified as HC
import Network.HTTP.Types          qualified as HT
import Network.HTTP2.Client        qualified as H2
import Network.TLS                 qualified as TLS
import Network.Wai                 (Application, Request, rawPathInfo)
import Network.Wai.Handler.Warp
    (InvalidRequest(..), Settings, defaultSettings, defaultShouldDisplayException, runSettings,
    setBeforeMainLoop, setHost, setLogger, setNoParsePath, setOnException, setPort, setServerName)
import Network.Wai.Handler.WarpTLS
    (OnInsecure(..), TLSSettings, WarpTLSException, defaultTlsSettings, onInsecure, runTLS,
    tlsAllowedVersions, tlsCredentials, tlsServerHooks, tlsSessionManager)

import System.IO.Error (ioeGetErrorType)

#ifdef QUIC_ENABLED
import Network.HProx.Platform.Quic
import Network.QUIC.Internal       qualified as Q
#endif

import Network.HProx.Config
import Network.HProx.DoH
import Network.HProx.Impl
import Network.HProx.Log
import Network.HProx.Route

data RuntimeConfig = RuntimeConfig
  { runtimeConfigLogOutput          :: !LogOutput
  , runtimeConfigReverseRoutes      :: ![ReverseRoute]
  , runtimeConfigReverseRouteTuples :: ![(Maybe BS8.ByteString, BS8.ByteString, BS8.ByteString)]
  }
  deriving (Eq, Show)

data ProxyRuntime = ProxyRuntime
  { runtimeProxySettings :: !ProxySettings
  , runtimeReverseRoutes :: ![(Maybe BS8.ByteString, BS8.ByteString, BS8.ByteString)]
  }

data WarpRuntimePlan = WarpRuntimePlan
  { runtimeBindHost    :: !String
  , runtimePort        :: !Int
  , runtimeServerName  :: !BS8.ByteString
  , runtimeNoParsePath :: !Bool
  } deriving (Eq, Show)

data RunnerPlan
  = PlainWarpRunner
  | TlsWarpRunner
  | QuicAndTlsRunner !Int
  deriving (Eq, Show)

data StartupStep
  = InitializeLogger
  | LogStartup
  | ReadCertificates
  | CreateTlsSessionManager
  | BuildSettingsAndRunner
  | LoadProxyAuth
  | CreateHttpManager
  | BuildProxyApplication
  | LogRuntimeConfig
  | StartRunner
  deriving (Eq, Show)

buildRuntimeConfig :: Config -> RuntimeConfig
buildRuntimeConfig Config{..} = RuntimeConfig
  { runtimeConfigLogOutput          = parseLogOutput _log
  , runtimeConfigReverseRoutes      = map fromReverseRouteTuple revSorted
  , runtimeConfigReverseRouteTuples = revSorted
  }
  where
    revSorted = sortOn (\(a,b,_) -> Down (isJust a, BS8.length b)) _rev

buildProxyRuntime :: RuntimeConfig -> Config -> Logger -> Maybe (BS8.ByteString -> Bool) -> Bool -> ProxyRuntime
buildProxyRuntime RuntimeConfig{..} Config{..} logger pauth isSSL = ProxyRuntime
  { runtimeProxySettings = ProxySettings
      { proxyAuth      = pauth
      , passPrompt     = Just _name
      , wsRemote       = _ws
      , revRemoteMap   = runtimeConfigReverseRoutes
      , hideProxyAuth  = _hide
      , naivePadding   = _naive && isSSL
      , acmeThumbprint = _acme
      , logger         = logger
      }
  , runtimeReverseRoutes = runtimeConfigReverseRouteTuples
  }

buildProxyApplication :: Bool -> ProxySettings -> HC.Manager -> Application -> Application
buildProxyApplication isSSL pset manager fallback =
  healthCheckProvider $
    acmeProvider pset $
      (if isSSL then forceSSL pset else id) $
        httpProxy pset manager $
          reverseProxy pset manager fallback

selectRunnerPlan :: Config -> [(String, a)] -> RunnerPlan
#ifdef QUIC_ENABLED
selectRunnerPlan Config{..} certs = case certs of
  [] -> PlainWarpRunner
  _  -> maybe TlsWarpRunner QuicAndTlsRunner _quic
#else
selectRunnerPlan _ certs = case certs of
  [] -> PlainWarpRunner
  _  -> TlsWarpRunner
#endif

shouldWrapDNSOverHTTPS :: Config -> Bool
shouldWrapDNSOverHTTPS Config{..} = isJust _doh

validateRuntimeConfig :: Config -> Either String ()
validateRuntimeConfig Config{..} = do
  validatePortField "--port" _port
#ifdef QUIC_ENABLED
  maybe (Right ()) (validatePortField "--quic") _quic
#endif

validatePortField :: String -> Int -> Either String ()
validatePortField field port
  | port >= 1 && port <= 65535 = Right ()
  | otherwise                  = Left $ "invalid " <> field <> ": " <> show port <> " (expected 1..65535)"

startupOrder :: [StartupStep]
startupOrder =
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

runProxyServer
  :: Config
  -> Logger
  -> Settings
  -> TLS.SessionManager
  -> [(String, TLS.Credential)]
  -> Application
  -> IO ()
runProxyServer conf@Config{..} logger settings sessionManager certs app = do
  logger INFO $ "bind to TCP port " <> toLogStr (fromMaybe "[::]" _bind) <> ":" <> toLogStr _port
  case _doh of
    Nothing  -> runner app
    Just doh -> createResolver doh (\resolver -> runner (dnsOverHTTPS resolver app))
  where
    runner = case (selectRunnerPlan conf certs, defaultCertificate certs) of
      (PlainWarpRunner, _) -> runSettings settings
      (TlsWarpRunner, Just defaultCert) ->
        runTLS (buildTlsSettings sessionManager certs defaultCert) settings
#ifdef QUIC_ENABLED
      (QuicAndTlsRunner qport, Just defaultCert) ->
        runQuicAndTls
          logger
          _bind
          settings
          (buildTlsSettings sessionManager certs defaultCert)
          lookupSNICredentials'
          sessionManager
          defaultCert
          qport
#endif
#ifndef QUIC_ENABLED
      (QuicAndTlsRunner _, Just defaultCert) ->
        runTLS (buildTlsSettings sessionManager certs defaultCert) settings
#endif
      (_, Nothing) -> runSettings settings
#ifdef QUIC_ENABLED
    lookupSNICredentials' host = lookupSNICredentials host certs
#endif

buildWarpRuntimePlan :: Config -> WarpRuntimePlan
buildWarpRuntimePlan Config{..} = WarpRuntimePlan
  { runtimeBindHost    = fromMaybe "*6" _bind
  , runtimePort        = _port
  , runtimeServerName  = _name
  , runtimeNoParsePath = True
  }

buildWarpSettings :: Config -> Logger -> Maybe (IO ()) -> Settings
buildWarpSettings config logger beforeMainLoop =
  applyBeforeMainLoop $
    setHost (fromString (runtimeBindHost plan)) $
      setPort (runtimePort plan) $
        setLogger (warpAccessLogger logger) $
          setOnException (runtimeExceptionHandler logger (_loglevel config)) $
            setNoParsePath (runtimeNoParsePath plan) $
              setServerName (runtimeServerName plan) defaultSettings
  where
    plan = buildWarpRuntimePlan config
    applyBeforeMainLoop = maybe id setBeforeMainLoop beforeMainLoop

runtimeExceptionHandler :: Logger -> LogLevel -> Maybe Request -> SomeException -> IO ()
runtimeExceptionHandler logger logLevel req ex =
  case runtimeExceptionToLog logLevel ex of
    Nothing    -> return ()
    Just ex' ->
      logger DEBUG $ "exception: " <> toLogStr (displayException ex') <>
        maybe "" (\req' -> " from: " <> logRequest req') req

warpAccessLogger :: Logger -> Request -> HT.Status -> Maybe Integer -> IO ()
warpAccessLogger logger req status _
  | shouldSuppressAccessLog req = return ()
  | otherwise                   =
      logger TRACE $ "(" <> toLogStr (HT.statusCode status) <> ") " <> logRequest req

shouldSuppressAccessLog :: Request -> Bool
shouldSuppressAccessLog req = rawPathInfo req == "/.hprox/health"

shouldIgnoreRuntimeException :: LogLevel -> SomeException -> Bool
shouldIgnoreRuntimeException logLevel ex = isNothing (runtimeExceptionToLog logLevel ex)

runtimeExceptionToLog :: LogLevel -> SomeException -> Maybe SomeException
runtimeExceptionToLog logLevel ex
  | logLevel > DEBUG                                      = Nothing
  | not (defaultShouldDisplayException ex)                = Nothing
  | Just ioe <- fromException ex
  , ioeGetErrorType ioe == EOF                            = Nothing
  | Just (H2.BadThingHappen ex') <- fromException ex       = runtimeExceptionToLog logLevel ex'
  | Just (_ :: H2.HTTP2Error) <- fromException ex          = Nothing
#ifdef QUIC_ENABLED
  | Just (Q.BadThingHappen ex') <- fromException ex        = runtimeExceptionToLog logLevel ex'
  | Just (_ :: Q.QUICException) <- fromException ex        = Nothing
#endif
  | Just (_ :: WarpTLSException) <- fromException ex       = Nothing
  | Just ConnectionClosedByPeer <- fromException ex        = Nothing
  | otherwise                                             = Just ex

loadTlsCredentials :: [(String, CertFile)] -> IO [(String, TLS.Credential)]
loadTlsCredentials certFiles = mapM readTlsCredential certFiles
  where
    readTlsCredential (name, CertFile cert key) = do
      loadedCredential <- try (TLS.credentialLoadX509 cert key)
      case loadedCredential of
        Left err -> failWithContext name cert key $ displayException (err :: IOException)
        Right (Left err) -> failWithContext name cert key err
        Right (Right credential) -> return (name, credential)

    failWithContext name cert key err =
      ioError $ userError $
        "failed to load TLS credential for " ++ show name ++
        " (certificate: " ++ cert ++ ", key: " ++ key ++ "): " ++ err

buildTlsSettings :: TLS.SessionManager -> [(String, TLS.Credential)] -> TLS.Credential -> TLSSettings
buildTlsSettings sessionManager certs defaultCert = defaultTlsSettings
  { tlsServerHooks     = def { TLS.onServerNameIndication = lookupSNICredentials' }
  , tlsCredentials     = Just (TLS.Credentials [defaultCert])
  , onInsecure         = AllowInsecure
  , tlsAllowedVersions = [TLS.TLS13, TLS.TLS12]
  , tlsSessionManager  = Just sessionManager
  }
  where
    lookupSNICredentials' host = lookupSNICredentials host certs

lookupSNICredentials :: Maybe String -> [(String, TLS.Credential)] -> IO TLS.Credentials
lookupSNICredentials host certs =
  either fail (return . TLS.Credentials . (: [])) (lookupSNIHost host certs)

defaultCertificate :: [(String, a)] -> Maybe a
defaultCertificate []              = Nothing
defaultCertificate ((_, cert) : _) = Just cert

lookupSNIHost :: Maybe String -> [(String, a)] -> Either String a
lookupSNIHost Nothing _ = Left "SNI: unspecified"
lookupSNIHost (Just host) certs = go certs
  where
    go [] = Left $ "SNI: unknown hostname (" ++ show host ++ ")"
    go ((pattern, value) : rest)
      | sniPatternMatches host pattern = Right value
      | otherwise                      = go rest

sniPatternMatches :: String -> String -> Bool
sniPatternMatches host pattern = case map asciiLower pattern of
  '*' : '.' : suffix -> singleLabelWildcardMatches (map asciiLower host) suffix
  exact              -> map asciiLower host == exact

singleLabelWildcardMatches :: String -> String -> Bool
singleLabelWildcardMatches host suffix =
  case break (== '.') host of
    ([], _)             -> False
    (label, '.' : rest) -> not (null label) && rest == suffix
    _                   -> False

asciiLower :: Char -> Char
asciiLower char
  | char >= 'A' && char <= 'Z' = toEnum (fromEnum char + 32)
  | otherwise                  = char
