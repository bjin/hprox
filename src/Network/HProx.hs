-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.
{-# LANGUAGE CPP #-}

{-| Instead of running @hprox@ binary directly, you can use this library
    to run HProx in front of arbitrary WAI 'Application'.
-}

module Network.HProx
  ( CertFile (..)
  , Config (..)
  , defaultConfig
  , getConfig
  , run
  ) where

import Data.ByteString.Char8       qualified as BS8
import Data.List                   (isSuffixOf, (\\))
import Data.String                 (fromString)
import Data.Version                (showVersion)
import Network.HTTP.Client.TLS     (newTlsManager)
import Network.TLS                 qualified as TLS
import Network.TLS.Extra.Cipher    qualified as TLS
import Network.TLS.SessionManager  qualified as SM
import Network.Wai                 (Application)
import Network.Wai.Handler.Warp
    (defaultSettings, runSettings, setBeforeMainLoop, setHost, setNoParsePath,
    setOnException, setPort, setServerName)
import Network.Wai.Handler.WarpTLS
    (OnInsecure (..), onInsecure, runTLS, tlsAllowedVersions, tlsCiphers,
    tlsServerHooks, tlsSessionManager, tlsSettings)
import System.Posix.User
    (UserEntry (..), getUserEntryForName, setUserID)

#ifdef QUIC_ENABLED
import Control.Concurrent.Async     (mapConcurrently_)
import Data.List                    (find)
import Network.QUIC.Internal        qualified as Q
import Network.Wai.Handler.Warp     (setAltSvc)
import Network.Wai.Handler.WarpQUIC (runQUIC)
#endif

import Data.Maybe
import Options.Applicative

import Network.HProx.DoH
import Network.HProx.Impl
    (ProxySettings (..), forceSSL, httpProxy, reverseProxy)
import Paths_hprox        (version)

-- | Configuration of HProx, see @hprox --help@ for details
data Config = Config
  { _bind  :: Maybe String
  , _port  :: Int
  , _ssl   :: [(String, CertFile)]
  , _user  :: Maybe String
  , _auth  :: Maybe FilePath
  , _ws    :: Maybe String
  , _rev   :: Maybe String
  , _doh   :: Maybe String
  , _naive :: Bool
#ifdef QUIC_ENABLED
  , _quic  :: Maybe Int
#endif
  }

-- | Default value of 'Config', same as running @hprox@ without arguments
defaultConfig :: Config
defaultConfig = Config Nothing 3000 [] Nothing Nothing Nothing Nothing Nothing False
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
                    <*> (fromMaybe 3000 <$> port)
                    <*> ssl
                    <*> user
                    <*> auth
                    <*> ws
                    <*> rev
                    <*> doh
                    <*> naive
#ifdef QUIC_ENABLED
                    <*> quic
#endif

    bind = optional $ strOption
        ( long "bind"
       <> short 'b'
       <> metavar "bind_ip"
       <> help "ip address to bind on (default: all interfaces)")

    port = optional $ option auto
        ( long "port"
       <> short 'p'
       <> metavar "port"
       <> help "port number (default 3000)")

    ssl = many $ option (eitherReader parseSSL)
        ( long "tls"
       <> short 's'
       <> metavar "hostname:cerfile:keyfile"
       <> help "enable TLS and specify a domain and associated TLS certificate (can be specified multiple times for multiple domains)")

    user = optional $ strOption
        ( long "user"
       <> short 'u'
       <> metavar "nobody"
       <> help "setuid after binding port")

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

#ifdef QUIC_ENABLED
    quic = optional $ option auto
        ( long "quic"
       <> short 'q'
       <> metavar "port"
       <> help "enable QUIC (HTTP/3) on UDP port")
#endif

setuid :: String -> IO ()
setuid user = getUserEntryForName user >>= setUserID . userID

-- | Read 'Config' from command line arguments
getConfig :: IO Config
getConfig = execParser parser

-- | Run HProx in front of fallback 'Application', with specified 'Config'
run :: Application -- ^ fallback application
    -> Config      -- ^ configuration
    -> IO ()
run fallback Config{..} = do

    let certfiles = _ssl
    certs <- mapM (readCert.snd) certfiles
    smgr <- SM.newSessionManager SM.defaultConfig

    let isSSL = not (null certfiles)
        (primaryHost, primaryCert) = head certfiles
        otherCerts = tail $ zip (map fst certfiles) certs

        settings = setHost (fromString (fromMaybe "*6" _bind)) $
                   setPort _port $
                   setOnException (\_ _ -> return ()) $
                   setNoParsePath True $
                   setServerName "Apache" $
                   maybe id (setBeforeMainLoop . setuid) _user
                   defaultSettings

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
               | Just qport <- _quic = \app -> mapConcurrently_ ($ app)
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
        Just f  -> Just . flip elem . filter (isJust . BS8.elemIndex ':') . BS8.lines <$> BS8.readFile f
    manager <- newTlsManager

    let pset = ProxySettings pauth Nothing (BS8.pack <$> _ws) (BS8.pack <$> _rev) (_naive && isSSL)
        proxy = (if isSSL then forceSSL pset else id) $
                httpProxy pset manager $
                reverseProxy pset manager $
                fallback

    case _doh of
        Nothing  -> runner proxy
        Just doh -> createResolver doh (\resolver -> runner (dnsOverHTTPS resolver proxy))
