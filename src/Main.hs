-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2019 Bin Jin. All Rights Reserved.
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Main where

import qualified Data.ByteString.Char8       as BS8
import           Data.String                 (fromString)
import           Network.HTTP.Client.TLS     (newTlsManager)
import           Network.TLS                 as TLS
import           Network.Wai.Handler.Warp    (HostPreference, defaultSettings,
                                              runSettings, setBeforeMainLoop,
                                              setHost, setNoParsePath,
                                              setOnException, setPort,
                                              setServerName)
import           Network.Wai.Handler.WarpTLS (OnInsecure (..), onInsecure,
                                              runTLS, tlsServerHooks,
                                              tlsSettings)
import           Network.Wai.Middleware.Gzip (def, gzip)
import           System.Posix.User           (UserEntry (..),
                                              getUserEntryForName, setUserID)

import           Data.Maybe
import           Data.Version                (showVersion)
import           Options.Applicative

import           DoH
import           HProx                       (ProxySettings (..), dumbApp,
                                              forceSSL, httpProxy, reverseProxy)
import           Paths_hprox                 (version)

data Opts = Opts
  { _bind :: Maybe HostPreference
  , _port :: Int
  , _ssl  :: [(String, CertFile)]
  , _user :: Maybe String
  , _auth :: Maybe FilePath
  , _ws   :: Maybe String
  , _rev  :: Maybe String
  , _doh  :: Maybe String
  }

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

parser :: ParserInfo Opts
parser = info (helper <*> ver <*> opts) (fullDesc <> progDesc desc)
  where
    parseSSL s = case splitBy ':' s of
        [host, cert, key] -> Right (host, CertFile cert key)
        _                 -> Left "invalid format for ssl certificates"

    desc = "a lightweight HTTP proxy server, and more"
    ver = infoOption (showVersion version) (long "version" <> help "show version")

    opts = Opts <$> bind
                <*> (fromMaybe 3000 <$> port)
                <*> ssl
                <*> user
                <*> auth
                <*> ws
                <*> rev
                <*> doh

    bind = optional $ fromString <$> strOption
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
       <> help "enable doh (dns-over-https) support")


setuid :: String -> IO ()
setuid user = getUserEntryForName user >>= setUserID . userID

main :: IO ()
main = do
    Opts{..} <- execParser parser

    let certfiles = _ssl
    certs <- mapM (readCert.snd) certfiles

    let isSSL = not (null certfiles)
        (primaryHost, primaryCert) = head certfiles
        otherCerts = tail $ zip (map fst certfiles) certs

        settings = setHost (fromMaybe "*6" _bind) $
                   setPort _port $
                   setOnException (\_ _ -> return ()) $
                   setNoParsePath True $
                   setServerName "Apache" $
                   maybe id (setBeforeMainLoop . setuid) _user
                   defaultSettings

        tlsset' = tlsSettings (certfile primaryCert) (keyfile primaryCert)
        hooks = (tlsServerHooks tlsset') { onServerNameIndication = onSNI }
        tlsset = tlsset' { tlsServerHooks = hooks, onInsecure = AllowInsecure }

        onSNI Nothing = fail "SNI: unspecified"
        onSNI (Just host)
          | host == primaryHost = return mempty
          | otherwise           = case lookup host otherCerts of
              Nothing   -> fail ("SNI: unknown hostname (" ++ show host ++ ")")
              Just cert -> return (TLS.Credentials [cert])

        runner | isSSL     = runTLS tlsset
               | otherwise = runSettings

    pauth <- case _auth of
        Nothing -> return Nothing
        Just f  -> Just . flip elem . filter (isJust . BS8.elemIndex ':') . BS8.lines <$> BS8.readFile f
    manager <- newTlsManager

    let pset = ProxySettings pauth Nothing (BS8.pack <$> _ws) (BS8.pack <$> _rev)
        proxy = (if isSSL then forceSSL pset else id) $ gzip def $ httpProxy pset manager $ reverseProxy pset manager dumbApp

    case _doh of
        Nothing  -> runner settings proxy
        Just doh -> createResolver doh (\resolver -> runner settings (dnsOverHTTPS resolver proxy))
