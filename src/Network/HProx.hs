-- SPDX-License-Identifier: Apache-2.0

-- Copyright (C) 2023 Bin Jin. All Rights Reserved.
{-# LANGUAGE CPP                 #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns        #-}

{-| Instead of running @hprox@ binary directly, you can use this library
    to run HProx in front of arbitrary WAI 'Application'.
-}

module Network.HProx
  ( CertFile (..)
  , Config (..)
  , LogLevel (..)
  , defaultConfig
  , getConfig
  , run
  ) where

import Data.ByteString.Char8       qualified as BS8
import Data.Default.Class          (def)
import Data.HashMap.Strict         qualified as HM
import Data.List
    (elemIndex, elemIndices, find, isSuffixOf, sortOn, (\\))
import Data.Ord                    (Down (..))
import Data.String                 (fromString)
import Data.Version                (showVersion)
import Network.HTTP.Client.TLS     (newTlsManager)
import Network.HTTP.Types          qualified as HT
import Network.TLS                 qualified as TLS
import Network.TLS.Extra.Cipher    qualified as TLS
import Network.TLS.SessionManager  qualified as SM
import Network.Wai                 (Application, rawPathInfo)
import Network.Wai.Handler.Warp
    (InvalidRequest (..), defaultSettings, defaultShouldDisplayException,
    runSettings, setHost, setLogger, setNoParsePath, setOnException, setPort,
    setServerName)
import Network.Wai.Handler.WarpTLS
    (OnInsecure (..), WarpTLSException, defaultTlsSettings, onInsecure, runTLS,
    tlsAllowedVersions, tlsCiphers, tlsCredentials, tlsServerHooks,
    tlsSessionManager)

import Control.Exception    (Exception (..))
import GHC.IO.Exception     (IOErrorType (..))
import Network.HTTP2.Client qualified as H2
import System.IO.Error      (ioeGetErrorType)

#ifdef QUIC_ENABLED
import Control.Concurrent.Async     (mapConcurrently_)
import Network.QUIC                 qualified as Q
import Network.QUIC.Internal        qualified as Q
import Network.Wai.Handler.Warp     (setAltSvc)
import Network.Wai.Handler.WarpQUIC (runQUIC)
#endif

#ifdef OS_UNIX
import Network.Wai.Handler.Warp
    (setGracefulShutdownTimeout, setInstallShutdownHandler)
import System.Posix.Signals
#endif

import Control.Monad
import Data.Maybe
import Options.Applicative

import Network.HProx.DoH
import Network.HProx.Impl
import Network.HProx.Log
import Network.HProx.Util
import Paths_hprox

-- | Configuration of HProx, see @hprox --help@ for details
data Config = Config
  { _bind     :: Maybe String
  , _port     :: Int
  , _ssl      :: [(String, CertFile)]
  , _auth     :: Maybe FilePath
  , _ws       :: Maybe BS8.ByteString
  , _rev      :: [(Maybe BS8.ByteString, BS8.ByteString, BS8.ByteString)]
  , _doh      :: Maybe String
  , _hide     :: Bool
  , _naive    :: Bool
  , _name     :: BS8.ByteString
  , _acme     :: Maybe BS8.ByteString
  , _log      :: String
  , _loglevel :: LogLevel
#ifdef QUIC_ENABLED
  , _quic     :: Maybe Int
#endif
  }

-- | Default value of 'Config', same as running @hprox@ without arguments
defaultConfig :: Config
defaultConfig = Config Nothing 3000 [] Nothing Nothing [] Nothing False False "hprox" Nothing "stdout" INFO
#ifdef QUIC_ENABLED
    Nothing
#endif

-- | Certificate file pairs
data CertFile = CertFile
  { certfile :: FilePath
  , keyfile  :: FilePath
  }

readCert :: CertFile -> IO TLS.Credential
readCert (CertFile c k) = either error id <$> TLS.credentialLoadX509 c k

parser :: ParserInfo Config
parser = info (helper <*> ver <*> config) (fullDesc <> progDesc desc)
  where
    parseSSL s = case splitBy ':' s of
        [host, cert, key] -> Right (host, CertFile cert key)
        _                 -> Left "invalid format for ssl certificates"

    parseRev0 s@('/':_) = case elemIndices '/' s of
        []      -> Nothing
        indices -> let (prefix, remote) = splitAt (last indices + 1) s
                   in Just (Nothing, BS8.pack prefix, BS8.pack remote)
    parseRev0 remote = Just (Nothing, "/", BS8.pack remote)

    parseRev ('/':'/':s) = case elemIndex '/' s of
        Nothing  -> Nothing
        Just ind -> let (domain, other) = splitAt ind s
                    in do (_, prefix, remote) <- parseRev0 other
                          return (Just (BS8.pack domain), prefix, remote)

    parseRev s = parseRev0 s

    desc = "a lightweight HTTP proxy server, and more"
    ver = infoOption (showVersion version) (long "version" <> help "Display the version information")

    config = Config <$> bind
                    <*> port
                    <*> ssl
                    <*> auth
                    <*> ws
                    <*> rev
                    <*> doh
                    <*> hide
                    <*> naive
                    <*> name
                    <*> acme
                    <*> logging
                    <*> loglevel
#ifdef QUIC_ENABLED
                    <*> quic
#endif

    bind = optional $ strOption
        ( long "bind"
       <> short 'b'
       <> metavar "bind_ip"
       <> help "Specify the IP address to bind to (default: all interfaces)")

    port = option auto
        ( long "port"
       <> short 'p'
       <> metavar "port"
       <> value 3000
       <> showDefault
       <> help "Specify the port number")

    ssl = many $ option (eitherReader parseSSL)
        ( long "tls"
       <> short 's'
       <> metavar "hostname:cerfile:keyfile"
       <> help "Enable TLS and specify a domain with its associated TLS certificate (can be specified multiple times for multiple domains)")

    auth = optional $ strOption
        ( long "auth"
       <> short 'a'
       <> metavar "userpass.txt"
       <> help "Specify the password file for proxy authentication. Plaintext passwords should be in the format 'user:pass' and will be automatically Argon2-hashed by hprox. Ensure that the password file with plaintext password is writable")

    ws = optional $ strOption
        ( long "ws"
       <> metavar "remote-host:port"
       <> help "Specify the remote host to handle WebSocket requests (port 443 indicates an HTTPS remote server)")

    rev = many $ option (maybeReader parseRev)
        ( long "rev"
       <> metavar "[//domain/][/prefix/]remote-host:port"
       <> help "Specify the remote host for reverse proxy (port 443 indicates an HTTPS remote server). An optional '//domain/' will only process requests with the 'Host: domain' header, and an optional '/prefix/' can be specified as a prefix to be matched (and stripped in proxied request)")

    doh = optional $ strOption
        ( long "doh"
       <> metavar "dns-server:port"
       <> help "Enable DNS-over-HTTPS (DoH) support (port 53 will be used if not specified)")

    hide = switch
        ( long "hide"
       <> help "Never send 'Proxy Authentication Required' response. Note that this might break the use of HTTPS proxy in browsers")

    naive = switch
        ( long "naive"
       <> help "Add naiveproxy-compatible padding (requires TLS)")

    name = strOption
        ( long "name"
       <> metavar "server-name"
       <> value "hprox"
       <> showDefault
       <> help "Specify the server name for the 'Server' header")

    acme = optional $ strOption
        ( long "acme"
       <> metavar "ACCOUNT_THUMBPRINT"
       <> help "Set the thumbprint for stateless http-01 ACME challenge as specified by RFC8555")

    logging = strOption
        ( long "log"
       <> metavar "<none|stdout|stderr|file>"
       <> value "stdout"
       <> showDefault
       <> help "Specify the logging type")

    loglevel = option (maybeReader logLevelReader)
        ( long "loglevel"
       <> metavar "<trace|debug|info|warn|error|none>"
       <> value INFO
       <> help "Specify the logging level (default: info)")

#ifdef QUIC_ENABLED
    quic = optional $ option auto
        ( long "quic"
       <> short 'q'
       <> metavar "port"
       <> help "Enable QUIC (HTTP/3) on UDP port")
#endif

getLoggerType :: String -> LogType' LogStr
getLoggerType "none"   = LogNone
getLoggerType "stdout" = LogStdout 4096
getLoggerType "stderr" = LogStderr 4096
getLoggerType file     = LogFileNoRotate file 4096

-- | Read 'Config' from command line arguments
getConfig :: IO Config
getConfig = execParser parser

-- | Run HProx in front of fallback 'Application', with specified 'Config'
run :: Application -- ^ fallback application
    -> Config      -- ^ configuration
    -> IO ()
run fallback Config{..} = withLogger (getLoggerType _log) _loglevel $ \logger -> do
    logger INFO $ "hprox " <> toLogStr (showVersion version) <> " started"
    logger INFO $ "bind to TCP port " <> toLogStr (fromMaybe "[::]" _bind) <> ":" <> toLogStr _port

    let certfiles = _ssl

    certs <- mapM (readCert.snd) certfiles
    smgr <- SM.newSessionManager SM.defaultConfig

    let isSSL = not (null certfiles)
        allCerts = zip (map fst certfiles) certs

    when isSSL $ do
        logger INFO $ "read " <> toLogStr (show $ length certs) <> " certificates"
        logger INFO $ "domains: " <> toLogStr (unwords $ map fst allCerts)

    let settings = setHost (fromString (fromMaybe "*6" _bind)) $
                   setPort _port $
                   setLogger warpLogger $
                   setOnException exceptionHandler $
#ifdef OS_UNIX
                   setGracefulShutdownTimeout (Just 3) $
                   setInstallShutdownHandler shutdownHandler $
#endif
                   setNoParsePath True $
                   setServerName _name defaultSettings

#ifdef OS_UNIX
        shutdownHandler closeSocket = do
            void $ installHandler sigTERM (CatchOnce $ logger INFO "Received SIGTERM signal, shutting down gracefully" >> closeSocket) Nothing
            void $ installHandler sigINT (CatchOnce $ logger INFO "Received SIGINT signal, shutting down gracefully" >> closeSocket) Nothing
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
                    (if isJust req then " from: " <> logRequest (fromJust req) else "")

        warpLogger req status _
            | rawPathInfo req == "/.hprox/health" = return ()
            | otherwise                           =
                logger TRACE $ "(" <> toLogStr (HT.statusCode status) <> ") " <> logRequest req

        -- https://www.ssllabs.com/ssltest
        weak_ciphers = [ TLS.cipher_ECDHE_RSA_AES256CBC_SHA384
                       , TLS.cipher_ECDHE_RSA_AES256CBC_SHA
                       , TLS.cipher_AES256CCM_SHA256
                       , TLS.cipher_AES256GCM_SHA384
                       , TLS.cipher_AES256_SHA256
                       , TLS.cipher_AES256_SHA1
                       ]

        tlsset = defaultTlsSettings
            { tlsServerHooks     = def { TLS.onServerNameIndication = onSNI }
            , tlsCredentials     = Just (TLS.Credentials certs)
            , onInsecure         = AllowInsecure
            , tlsAllowedVersions = [TLS.TLS13, TLS.TLS12]
            , tlsCiphers         = TLS.ciphersuite_strong \\ weak_ciphers
            , tlsSessionManager  = Just smgr
            }

        onSNI Nothing     = fail "SNI: unspecified"
        onSNI (Just host) = lookupSNI host allCerts

        lookupSNI host [] = fail ("SNI: unknown hostname (" ++ show host ++ ")")
        lookupSNI host ((p, cert) : cs)
          | checkSNI host p = return (TLS.Credentials [cert])
          | otherwise       = lookupSNI host cs

        checkSNI host pat = case pat of
            '*' : '.' : p -> ('.' : p) `isSuffixOf` host
            p             -> host == p

#ifdef QUIC_ENABLED
        alpn _ = return . fromMaybe "" . find (== "h3")
        altsvc qport = BS8.concat ["h3=\":", BS8.pack $ show qport ,"\""]

        quicset qport = Q.defaultServerConfig
            { Q.scAddresses      = [(fromString (fromMaybe "0.0.0.0" _bind), fromIntegral qport)]
            , Q.scVersions       = [Q.Version1, Q.Version2]
            , Q.scCredentials    = TLS.Credentials certs
            , Q.scCiphers        = Q.scCiphers Q.defaultServerConfig \\ weak_ciphers
            , Q.scALPN           = Just alpn
            , Q.scTlsHooks       = def { TLS.onServerNameIndication = onSNI }
            , Q.scUse0RTT        = True
            , Q.scSessionManager = smgr
            }

        runner | not isSSL           = runSettings settings
               | Just qport <- _quic = \app -> do
                    logger INFO $ "bind to UDP port " <> toLogStr (fromMaybe "0.0.0.0" _bind) <> ":" <> toLogStr qport
                    mapConcurrently_ ($ app)
                        [ runQUIC (quicset qport) settings
                        , runTLS tlsset (setAltSvc (altsvc qport) settings)
                        ]
               | otherwise           = runTLS tlsset settings
#else
        runner | isSSL     = runTLS tlsset settings
               | otherwise = runSettings settings
#endif

    pauth <- case _auth of
        Nothing -> return Nothing
        Just f  -> do
            logger INFO $ "read username and passwords from " <> toLogStr f
            userList <- BS8.lines <$> BS8.readFile f
            let anyPlaintext = any (\line -> length (BS8.elemIndices ':' line) /= 2) userList
                processUser userpass = case passwordReader userpass of
                    Nothing           -> do
                        logger WARN $ "unable to parse line from password file: " <> toLogStr userpass
                        return Nothing
                    Just (user, pass) -> do
                        salted <- hashPasswordWithRandomSalt pass
                        logger TRACE $ "parsed user (with salted password) from password file: " <> toLogStr (passwordWriter user salted)
                        return $ Just (user, salted)
            passwordByUser <- HM.fromList . catMaybes <$> mapM processUser userList
            when anyPlaintext $ do
                logger INFO $ "writing back to password file " <> toLogStr f
                BS8.writeFile f (BS8.unlines [ passwordWriter u p | (u, p) <- HM.toList passwordByUser])
            let verify line = do
                    idx <- BS8.elemIndex ':' line
                    let user = BS8.take idx line
                        pass = BS8.drop (idx + 1) line
                    targetPass <- HM.lookup user passwordByUser
                    return $ verifyPassword targetPass pass
            return $ Just (\line -> verify line == Just True)

    manager <- newTlsManager

    let revSorted = sortOn (\(a,b,_) -> Down (isJust a, BS8.length b)) _rev
        pset = ProxySettings pauth (Just _name) _ws revSorted _hide (_naive && isSSL) _acme logger
        proxy = healthCheckProvider $
                acmeProvider pset $
                (if isSSL then forceSSL pset else id) $
                httpProxy pset manager $
                reverseProxy pset manager fallback

    when (isJust _ws) $ logger INFO $ "websocket redirect: " <> toLogStr (fromJust _ws)
    unless (null revSorted) $ logger INFO $ "reverse proxy: " <> toLogStr (show revSorted)
    when (isJust _doh) $ logger INFO $ "DNS-over-HTTPS redirect: " <> toLogStr (fromJust _doh)

    case _doh of
        Nothing  -> runner proxy
        Just doh -> createResolver doh (\resolver -> runner (dnsOverHTTPS resolver proxy))
