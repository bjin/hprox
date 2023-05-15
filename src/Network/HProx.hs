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
import Data.List                   (isSuffixOf, (\\))
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
    (OnInsecure (..), WarpTLSException, onInsecure, runTLS, tlsAllowedVersions,
    tlsCiphers, tlsServerHooks, tlsSessionManager, tlsSettings)

import Control.Exception    (Exception (..))
import GHC.IO.Exception     (IOErrorType (..))
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

import Control.Monad
import Data.Maybe
import Options.Applicative

import Network.HProx.DoH
import Network.HProx.Impl
import Network.HProx.Log
import Paths_hprox

-- | Configuration of HProx, see @hprox --help@ for details
data Config = Config
  { _bind     :: Maybe String
  , _port     :: Int
  , _ssl      :: [(String, CertFile)]
  , _auth     :: Maybe FilePath
  , _ws       :: Maybe String
  , _rev      :: Maybe String
  , _doh      :: Maybe String
  , _naive    :: Bool
  , _name     :: BS8.ByteString
  , _log      :: String
  , _loglevel :: LogLevel
#ifdef QUIC_ENABLED
  , _quic     :: Maybe Int
#endif
  }

-- | Default value of 'Config', same as running @hprox@ without arguments
defaultConfig :: Config
defaultConfig = Config Nothing 3000 [] Nothing Nothing Nothing Nothing False "hprox" "stdout" INFO
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

splitBy :: Eq a => a -> [a] -> [[a]]
splitBy _ [] = [[]]
splitBy c (x:xs)
  | c == x    = [] : splitBy c xs
  | otherwise = let y:ys = splitBy c xs in (x:y):ys

parser :: ParserInfo Config
parser = info (helper <*> ver <*> config) (fullDesc <> progDesc desc)
  where
    parseSSL s = case splitBy ':' s of
        [host, cert, key] -> Right (host, CertFile cert key)
        _                 -> Left "invalid format for ssl certificates"

    desc = "a lightweight HTTP proxy server, and more"
    ver = infoOption (showVersion version) (long "version" <> help "show version")

    config = Config <$> bind
                    <*> port
                    <*> ssl
                    <*> auth
                    <*> ws
                    <*> rev
                    <*> doh
                    <*> naive
                    <*> name
                    <*> logging
                    <*> loglevel
#ifdef QUIC_ENABLED
                    <*> quic
#endif

    bind = optional $ strOption
        ( long "bind"
       <> short 'b'
       <> metavar "bind_ip"
       <> help "ip address to bind on (default: all interfaces)")

    port = option auto
        ( long "port"
       <> short 'p'
       <> metavar "port"
       <> value 3000
       <> showDefault
       <> help "port number")

    ssl = many $ option (eitherReader parseSSL)
        ( long "tls"
       <> short 's'
       <> metavar "hostname:cerfile:keyfile"
       <> help "enable TLS and specify a domain and associated TLS certificate (can be specified multiple times for multiple domains)")

    auth = optional $ strOption
        ( long "auth"
       <> short 'a'
       <> metavar "userpass.txt"
       <> help "password file for proxy authentication (plain text file with lines each containing a colon separated user/password pair)")

    ws = optional $ strOption
        ( long "ws"
       <> metavar "remote-host:port"
       <> help "remote host to handle websocket requests (port 443 indicates HTTPS remote server)")

    rev = optional $ strOption
        ( long "rev"
       <> metavar "remote-host:port"
       <> help "remote host for reverse proxy (port 443 indicates HTTPS remote server)")

    doh = optional $ strOption
        ( long "doh"
       <> metavar "dns-server:port"
       <> help "enable DNS-over-HTTPS(DoH) support (53 will be used if port is not specified)")

    naive = switch
        ( long "naive"
       <> help "add naiveproxy compatible padding (requires TLS)")

    name = strOption
        ( long "name"
       <> metavar "server-name"
       <> value "hprox"
       <> showDefault
       <> help "specify the server name for the 'Server' header")

    logging = strOption
        ( long "log"
       <> metavar "<none|stdout|stderr|file>"
       <> value "stdout"
       <> showDefault
       <> help "specify the logging type")

    loglevel = option (maybeReader logLevelReader)
        ( long "loglevel"
       <> metavar "<trace|debug|info|warn|error|none>"
       <> value INFO
       <> help "specify the logging level (default: info)")

#ifdef QUIC_ENABLED
    quic = optional $ option auto
        ( long "quic"
       <> short 'q'
       <> metavar "port"
       <> help "enable QUIC (HTTP/3) on UDP port")
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
        (primaryHost, primaryCert) = head certfiles
        otherCerts = tail $ zip (map fst certfiles) certs

    when isSSL $ do
        logger INFO $ "read " <> toLogStr (show $ length certs) <> " certificates"
        logger INFO $ "primary domain: " <> toLogStr primaryHost
        logger INFO $ "other domains: " <> toLogStr (unwords $ map fst otherCerts)

    let settings = setHost (fromString (fromMaybe "*6" _bind)) $
                   setPort _port $
                   setLogger warpLogger $
                   setOnException exceptionHandler $
                   setNoParsePath True $
                   setServerName _name $
                   defaultSettings

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
                    (if (isJust req) then " from: " <> logRequest (fromJust req) else "")

        warpLogger req status _
            | rawPathInfo req == "/.hprox/health" = return ()
            | otherwise                           =
                logger TRACE $ "(" <> toLogStr (HT.statusCode status) <> ") " <> logRequest req

        tlsset' = tlsSettings (certfile primaryCert) (keyfile primaryCert)
        hooks = (tlsServerHooks tlsset') { TLS.onServerNameIndication = onSNI }

        -- https://www.ssllabs.com/ssltest
        weak_ciphers = [ TLS.cipher_ECDHE_RSA_AES256CBC_SHA384
                       , TLS.cipher_ECDHE_RSA_AES256CBC_SHA
                       , TLS.cipher_AES256CCM_SHA256
                       , TLS.cipher_AES256GCM_SHA384
                       , TLS.cipher_AES256_SHA256
                       , TLS.cipher_AES256_SHA1
                       ]

        tlsset = tlsset'
            { tlsServerHooks     = hooks
            , onInsecure         = AllowInsecure
            , tlsAllowedVersions = [TLS.TLS13, TLS.TLS12]
            , tlsCiphers         = TLS.ciphersuite_strong \\ weak_ciphers
            , tlsSessionManager  = Just smgr
            }

        onSNI Nothing = fail "SNI: unspecified"
        onSNI (Just host)
          | checkSNI host primaryHost = return mempty
          | otherwise                 = lookupSNI host otherCerts

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
            , Q.scCredentials    = TLS.Credentials [head certs]
            , Q.scCiphers        = Q.scCiphers Q.defaultServerConfig \\ weak_ciphers
            , Q.scALPN           = Just alpn
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
            Just . flip elem . filter (isJust . BS8.elemIndex ':') . BS8.lines <$> BS8.readFile f
    manager <- newTlsManager

    let pset = ProxySettings pauth (Just _name) (BS8.pack <$> _ws) (BS8.pack <$> _rev) (_naive && isSSL) logger
        proxy = healthCheckProvider $
                (if isSSL then forceSSL pset else id) $
                httpProxy pset manager $
                reverseProxy pset manager $
                fallback

    when (isJust _ws) $ logger INFO $ "websocket redirect: " <> toLogStr (fromJust _ws)
    when (isJust _rev) $ logger INFO $ "reverse proxy: " <> toLogStr (fromJust _rev)
    when (isJust _doh) $ logger INFO $ "DNS-over-HTTPS redirect: " <> toLogStr (fromJust _doh)

    case _doh of
        Nothing  -> runner proxy
        Just doh -> createResolver doh (\resolver -> runner (dnsOverHTTPS resolver proxy))
