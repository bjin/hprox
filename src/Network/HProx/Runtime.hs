-- SPDX-License-Identifier: Apache-2.0

-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

{-# LANGUAGE CPP                 #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.HProx.Runtime
  ( ProxyRuntime(..)
  , WarpRuntimePlan(..)
  , buildProxyApplication
  , buildProxyRuntime
  , buildTlsSettings
  , buildWarpRuntimePlan
  , buildWarpSettings
  , defaultCertificate
  , loadTlsCredentials
  , lookupSNICredentials
  , lookupSNIHost
  , runtimeExceptionToLog
  , shouldIgnoreRuntimeException
  , shouldSuppressAccessLog
  , sniPatternMatches
  ) where

import Control.Exception           (SomeException, displayException, fromException)
import Data.ByteString.Char8       qualified as BS8
import Data.Default.Class          (def)
import Data.List                   (isSuffixOf, sortOn)
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
    (InvalidRequest(..), Settings, defaultSettings, defaultShouldDisplayException,
    setBeforeMainLoop, setHost, setLogger, setNoParsePath, setOnException, setPort, setServerName)
import Network.Wai.Handler.WarpTLS
    (OnInsecure(..), TLSSettings, WarpTLSException, defaultTlsSettings, onInsecure,
    tlsAllowedVersions, tlsCredentials, tlsServerHooks, tlsSessionManager)

import System.IO.Error (ioeGetErrorType)

#ifdef QUIC_ENABLED
import Network.QUIC.Internal qualified as Q
#endif

import Network.HProx.Config
import Network.HProx.Impl
import Network.HProx.Log
import Network.HProx.Route

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

buildProxyRuntime :: Config -> Logger -> Maybe (BS8.ByteString -> Bool) -> Bool -> ProxyRuntime
buildProxyRuntime Config{..} logger pauth isSSL = ProxyRuntime
  { runtimeProxySettings = ProxySettings
      { proxyAuth      = pauth
      , passPrompt     = Just _name
      , wsRemote       = _ws
      , revRemoteMap   = map fromReverseRouteTuple revSorted
      , hideProxyAuth  = _hide
      , naivePadding   = _naive && isSSL
      , acmeThumbprint = _acme
      , logger         = logger
      }
  , runtimeReverseRoutes = revSorted
  }
  where
    revSorted = sortOn (\(a,b,_) -> Down (isJust a, BS8.length b)) _rev

buildProxyApplication :: Bool -> ProxySettings -> HC.Manager -> Application -> Application
buildProxyApplication isSSL pset manager fallback =
  healthCheckProvider $
    acmeProvider pset $
      (if isSSL then forceSSL pset else id) $
        httpProxy pset manager $
          reverseProxy pset manager fallback


buildWarpRuntimePlan :: Config -> WarpRuntimePlan
buildWarpRuntimePlan Config{..} = WarpRuntimePlan
  { runtimeBindHost = fromMaybe "*6" _bind
  , runtimePort = _port
  , runtimeServerName = _name
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
  | otherwise =
      logger TRACE $ "(" <> toLogStr (HT.statusCode status) <> ") " <> logRequest req

shouldSuppressAccessLog :: Request -> Bool
shouldSuppressAccessLog req = rawPathInfo req == "/.hprox/health"

shouldIgnoreRuntimeException :: LogLevel -> SomeException -> Bool
shouldIgnoreRuntimeException logLevel ex = isNothing (runtimeExceptionToLog logLevel ex)

runtimeExceptionToLog :: LogLevel -> SomeException -> Maybe SomeException
runtimeExceptionToLog logLevel ex
  | logLevel > DEBUG = Nothing
  | not (defaultShouldDisplayException ex) = Nothing
  | Just ioe <- fromException ex
  , ioeGetErrorType ioe == EOF = Nothing
  | Just (H2.BadThingHappen ex') <- fromException ex = runtimeExceptionToLog logLevel ex'
  | Just (_ :: H2.HTTP2Error) <- fromException ex = Nothing
#ifdef QUIC_ENABLED
  | Just (Q.BadThingHappen ex') <- fromException ex = runtimeExceptionToLog logLevel ex'
  | Just (_ :: Q.QUICException) <- fromException ex = Nothing
#endif
  | Just (_ :: WarpTLSException) <- fromException ex = Nothing
  | Just ConnectionClosedByPeer <- fromException ex = Nothing
  | otherwise = Just ex

loadTlsCredentials :: [(String, CertFile)] -> IO [(String, TLS.Credential)]
loadTlsCredentials certFiles =
  zip (map fst certFiles) <$> mapM (readTlsCredential . snd) certFiles
  where
    readTlsCredential (CertFile cert key) = either error id <$> TLS.credentialLoadX509 cert key

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
sniPatternMatches host pattern = case pattern of
  '*' : '.' : suffix -> ('.' : suffix) `isSuffixOf` host
  exact              -> host == exact
