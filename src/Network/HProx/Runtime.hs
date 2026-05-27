-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

{-# LANGUAGE CPP                 #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.HProx.Runtime
  ( LoadedCredential(..)
  , RunnerPlan(..)
  , RuntimeConfig(..)
  , TlsCredentialLoader
  , TlsCredentialStore
  , WarpRuntimePlan(..)
  , buildProxyApplication
  , buildProxySettings
  , buildRuntimeConfig
  , buildTlsSettings
  , buildWarpRuntimePlan
  , buildWarpSettings
  , loadTlsCredentialFromMemory
  , loadTlsCredentialStore
  , loadTlsCredentials
  , lookupSNICredentials
  , lookupSNICredentialsFromStore
  , lookupSNIHost
  , lookupTlsCredentialStore
  , newTlsCredentialStore
  , readTlsCredentialStore
  , reloadTlsCredentialStore
  , runProxyServer
  , runtimeExceptionToLog
  , selectRunnerPlan
  , shouldSuppressAccessLog
  , sniPatternMatches
  , validateRuntimeConfig
  ) where

import Control.Concurrent.MVar     (MVar, newMVar, withMVar)
import Control.Exception
    (IOException, SomeException, displayException, fromException, try)
import Control.Monad               (zipWithM)
import Crypto.Hash                 qualified as Hash
import Data.ByteString             qualified as BS
import Data.ByteString.Char8       qualified as BS8
import Data.Default.Class          (def)
import Data.IORef                  (IORef, atomicWriteIORef, newIORef, readIORef)
import Data.List                   (sortOn)
import Data.Maybe                  (fromMaybe, isJust)
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
import Network.HProx.Quic
import Network.QUIC.Internal qualified as Q
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

data WarpRuntimePlan = WarpRuntimePlan
    { runtimeBindHost    :: !String
    , runtimePort        :: !Int
    , runtimeServerName  :: !BS8.ByteString
    , runtimeNoParsePath :: !Bool
    }
  deriving (Eq, Show)

data RunnerPlan
    = PlainWarpRunner
    | TlsWarpRunner
    | QuicAndTlsRunner !Int
  deriving (Eq, Show)

data LoadedCredential credential = LoadedCredential
    { loadedCredentialValue                  :: !credential
    , loadedCredentialCertificateFingerprint :: !(Hash.Digest Hash.SHA256)
    , loadedCredentialKeyFingerprint         :: !(Hash.Digest Hash.SHA256)
    }
  deriving (Eq, Show)

type TlsCredentialLoader credential =
    CertFile -> IO (Either String (LoadedCredential credential))

data TlsCredentialStore credential = TlsCredentialStore
    { tlsCredentialStoreSources    :: ![(String, CertFile)]
    , tlsCredentialStoreSnapshot   :: !(IORef [(String, LoadedCredential credential)])
    , tlsCredentialStoreReloadLock :: !(MVar ())
    , tlsCredentialStoreLoader     :: !(TlsCredentialLoader credential)
    }

buildRuntimeConfig :: Config -> RuntimeConfig
buildRuntimeConfig Config{..} = RuntimeConfig
    { runtimeConfigLogOutput          = parseLogOutput _log
    , runtimeConfigReverseRoutes      = map fromReverseRouteTuple revSorted
    , runtimeConfigReverseRouteTuples = revSorted
    }
  where
    revSorted = sortOn (\(a,b,_) -> Down (isJust a, BS8.length b)) _rev

buildProxySettings :: RuntimeConfig -> Config -> Logger -> Maybe (BS8.ByteString -> Bool) -> Bool -> ProxySettings
buildProxySettings RuntimeConfig{..} Config{..} logger pauth isSSL = ProxySettings
    { proxyAuth      = pauth
    , passPrompt     = Just _name
    , wsRemote       = _ws
    , revRemoteMap   = runtimeConfigReverseRoutes
    , hideProxyAuth  = _hide
    , naivePadding   = _naive && isSSL
    , acmeThumbprint = _acme
    , logger         = logger
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

runProxyServer
    :: Config
    -> Logger
    -> Settings
    -> TlsCredentialStore TLS.Credential
    -> Application
    -> IO ()
runProxyServer conf@Config{..} logger settings credentialStore app = do
    logger INFO $ "bind to TCP port " <> toLogStr (fromMaybe "[::]" _bind) <> ":" <> toLogStr _port
    case _doh of
        Nothing  -> runner app
        Just doh -> createResolver doh (\resolver -> runner (dnsOverHTTPS resolver app))
    where
      runner = case selectRunnerPlan conf (tlsCredentialStoreSources credentialStore) of
          PlainWarpRunner -> runSettings settings
          TlsWarpRunner ->
              runTLS (buildTlsSettings lookupSNICredentials') settings
#ifdef QUIC_ENABLED
          QuicAndTlsRunner qport ->
              runQuicAndTls
                logger
                _bind
                settings
                (buildTlsSettings lookupSNICredentials')
                lookupSNICredentials'
                qport
#else
          QuicAndTlsRunner _ ->
              runTLS (buildTlsSettings lookupSNICredentials') settings
#endif

      lookupSNICredentials' host = lookupSNICredentialsFromStore host credentialStore

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

runtimeExceptionToLog :: LogLevel -> SomeException -> Maybe SomeException
runtimeExceptionToLog logLevel ex
    | logLevel > DEBUG                                 = Nothing
    | not (defaultShouldDisplayException ex)           = Nothing
    | Just ioe <- fromException ex
    , ioeGetErrorType ioe == EOF                       = Nothing
    | Just (H2.BadThingHappen ex') <- fromException ex = runtimeExceptionToLog logLevel ex'
    | Just (_ :: H2.HTTP2Error) <- fromException ex    = Nothing
#ifdef QUIC_ENABLED
    | Just (Q.BadThingHappen ex') <- fromException ex  = runtimeExceptionToLog logLevel ex'
    | Just (_ :: Q.QUICException) <- fromException ex  = Nothing
#endif
    | Just (_ :: WarpTLSException) <- fromException ex = Nothing
    | Just ConnectionClosedByPeer <- fromException ex  = Nothing
    | otherwise                                        = Just ex

loadTlsCredentialStore :: [(String, CertFile)] -> IO (TlsCredentialStore TLS.Credential)
loadTlsCredentialStore = newTlsCredentialStore loadTlsCredential

loadTlsCredentials :: [(String, CertFile)] -> IO [(String, TLS.Credential)]
loadTlsCredentials certFiles = readTlsCredentialStore =<< loadTlsCredentialStore certFiles

newTlsCredentialStore
    :: TlsCredentialLoader credential
    -> [(String, CertFile)]
    -> IO (TlsCredentialStore credential)
newTlsCredentialStore loader certFiles = do
    loadedCredentials <- mapM (loadInitialTlsCredential loader) certFiles
    snapshot <- newIORef loadedCredentials
    reloadLock <- newMVar ()
    return TlsCredentialStore
        { tlsCredentialStoreSources    = certFiles
        , tlsCredentialStoreSnapshot   = snapshot
        , tlsCredentialStoreReloadLock = reloadLock
        , tlsCredentialStoreLoader     = loader
        }

readTlsCredentialStore :: TlsCredentialStore credential -> IO [(String, credential)]
readTlsCredentialStore TlsCredentialStore{..} =
    map (fmap loadedCredentialValue) <$> readIORef tlsCredentialStoreSnapshot

reloadTlsCredentialStore :: Logger -> TlsCredentialStore credential -> IO ()
reloadTlsCredentialStore logger store@TlsCredentialStore{..} =
    withMVar tlsCredentialStoreReloadLock $ \() -> do
        logger INFO "SIGHUP received; reloading TLS certificates"
        oldSnapshot <- readIORef tlsCredentialStoreSnapshot
        newSnapshot <- zipWithM (reloadTlsCredential logger store) tlsCredentialStoreSources oldSnapshot
        atomicWriteIORef tlsCredentialStoreSnapshot newSnapshot
        logger INFO "TLS certificate reload completed"

loadInitialTlsCredential
    :: TlsCredentialLoader credential
    -> (String, CertFile)
    -> IO (String, LoadedCredential credential)
loadInitialTlsCredential loader (name, certFile) = do
    loaded <- try (loader certFile)
    case loaded of
        Left (err :: IOException) -> failWithTlsCredentialContext name certFile $ displayException err
        Right (Left err)          -> failWithTlsCredentialContext name certFile err
        Right (Right credential)  -> return (name, credential)

reloadTlsCredential
    :: Logger
    -> TlsCredentialStore credential
    -> (String, CertFile)
    -> (String, LoadedCredential credential)
    -> IO (String, LoadedCredential credential)
reloadTlsCredential logger TlsCredentialStore{..} (name, certFile) (_, oldCredential) = do
    loaded <- try (tlsCredentialStoreLoader certFile)
    case loaded of
        Left (err :: IOException) -> reloadFailed $ displayException err
        Right (Left err)          -> reloadFailed err
        Right (Right credential)
            | loadedCredentialBytesChanged oldCredential credential -> do
                logger INFO $ "installed reloaded TLS credential for " <> toLogStr (show name) <>
                    " (certificate: " <> toLogStr (certfile certFile) <>
                    ", key: " <> toLogStr (keyfile certFile) <> ")"
                return (name, credential)
            | otherwise -> return (name, oldCredential)
  where
    reloadFailed err = do
        logTlsCredentialReloadFailure logger name certFile err
        return (name, oldCredential)

loadedCredentialBytesChanged :: LoadedCredential credential -> LoadedCredential credential -> Bool
loadedCredentialBytesChanged oldCredential newCredential =
    loadedCredentialCertificateFingerprint oldCredential /= loadedCredentialCertificateFingerprint newCredential ||
    loadedCredentialKeyFingerprint oldCredential /= loadedCredentialKeyFingerprint newCredential

loadTlsCredential :: TlsCredentialLoader TLS.Credential
loadTlsCredential (CertFile cert key) = do
    certBytes <- BS.readFile cert
    keyBytes <- BS.readFile key
    return $ loadTlsCredentialFromMemory certBytes keyBytes

loadTlsCredentialFromMemory :: BS.ByteString -> BS.ByteString -> Either String (LoadedCredential TLS.Credential)
loadTlsCredentialFromMemory certBytes keyBytes =
    case TLS.credentialLoadX509FromMemory certBytes keyBytes of
        Left err -> Left err
        Right credential@(TLS.CertificateChain chain, _)
            | null chain -> Left "loaded TLS credential has an empty certificate chain"
            | otherwise  -> Right LoadedCredential
                { loadedCredentialValue                  = credential
                , loadedCredentialCertificateFingerprint = fingerprintBytes certBytes
                , loadedCredentialKeyFingerprint         = fingerprintBytes keyBytes
                }

fingerprintBytes :: BS.ByteString -> Hash.Digest Hash.SHA256
fingerprintBytes = Hash.hash

failWithTlsCredentialContext :: String -> CertFile -> String -> IO a
failWithTlsCredentialContext name (CertFile cert key) err =
    ioError $ userError $
        "failed to load TLS credential for " ++ show name ++
        " (certificate: " ++ cert ++ ", key: " ++ key ++ "): " ++ err

logTlsCredentialReloadFailure :: Logger -> String -> CertFile -> String -> IO ()
logTlsCredentialReloadFailure logger name (CertFile cert key) err =
    logger ERROR $
        "failed to reload TLS credential for " <> toLogStr (show name) <>
        " (certificate: " <> toLogStr cert <>
        ", key: " <> toLogStr key <> "): " <> toLogStr err

buildTlsSettings :: (Maybe String -> IO TLS.Credentials) -> TLSSettings
buildTlsSettings onSNI = defaultTlsSettings
    { tlsServerHooks     = def { TLS.onServerNameIndication = onSNI }
    , tlsCredentials     = Just (TLS.Credentials [])
    , onInsecure         = AllowInsecure
    , tlsAllowedVersions = [TLS.TLS13, TLS.TLS12]
    , tlsSessionManager  = Nothing
    }

lookupSNICredentials :: Maybe String -> [(String, TLS.Credential)] -> IO TLS.Credentials
lookupSNICredentials host certs =
    either fail (return . TLS.Credentials . (: [])) (lookupSNIHost host certs)

lookupSNICredentialsFromStore :: Maybe String -> TlsCredentialStore TLS.Credential -> IO TLS.Credentials
lookupSNICredentialsFromStore host store =
    TLS.Credentials . (: []) <$> lookupTlsCredentialStore host store

lookupTlsCredentialStore :: Maybe String -> TlsCredentialStore credential -> IO credential
lookupTlsCredentialStore host TlsCredentialStore{..} = do
    snapshot <- readIORef tlsCredentialStoreSnapshot
    case host of
        Nothing ->
            case snapshot of
                []             -> fail "SNI: no TLS credentials configured"
                (_, value) : _ -> return $ loadedCredentialValue value
        Just _ ->
            either fail (return . loadedCredentialValue) (lookupSNIHost host snapshot)


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
