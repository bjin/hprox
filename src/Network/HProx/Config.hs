-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.
{-# LANGUAGE CPP #-}

module Network.HProx.Config
  ( CertFile(..)
  , Config(..)
  , defaultConfig
  , getConfig
  ) where

import Data.ByteString.Char8 qualified as BS8
import Data.List             (elemIndex, elemIndices)
import Data.List.NonEmpty    (NonEmpty(..))
import Data.Version          (showVersion)
import Options.Applicative

import Network.HProx.Log
import Network.HProx.Util
import Paths_hprox

-- | Configuration of HProx, see @hprox --help@ for details
data Config = Config
    { _bind     :: !(Maybe String)
    , _port     :: !Int
    , _ssl      :: ![(String, CertFile)]
    , _auth     :: !(Maybe FilePath)
    , _ws       :: !(Maybe BS8.ByteString)
    , _rev      :: ![(Maybe BS8.ByteString, BS8.ByteString, BS8.ByteString)]
    , _doh      :: !(Maybe String)
    , _hide     :: !Bool
    , _naive    :: !Bool
    , _name     :: !BS8.ByteString
    , _acme     :: !(Maybe BS8.ByteString)
    , _log      :: !String
    , _loglevel :: !LogLevel
#ifdef OS_UNIX
    , _user     :: !(Maybe String)
    , _group    :: !(Maybe String)
#endif
#ifdef QUIC_ENABLED
    , _quic     :: !(Maybe Int)
#endif
    }

-- | Default value of 'Config', same as running @hprox@ without arguments
defaultConfig :: Config
defaultConfig = Config
    { _bind     = Nothing
    , _port     = 3000
    , _ssl      = []
    , _auth     = Nothing
    , _ws       = Nothing
    , _rev      = []
    , _doh      = Nothing
    , _hide     = False
    , _naive    = False
    , _name     = "hprox"
    , _acme     = Nothing
    , _log      = "stdout"
    , _loglevel = INFO
#ifdef OS_UNIX
    , _user     = Nothing
    , _group    = Nothing
#endif
#ifdef QUIC_ENABLED
    , _quic     = Nothing
#endif
    }

-- | Certificate file pairs
data CertFile = CertFile
    { certfile :: !FilePath
    , keyfile  :: !FilePath
    }

parser :: ParserInfo Config
parser = info (helper <*> ver <*> config) (fullDesc <> progDesc desc)
  where
    parseBoundedPort optionName raw =
        case reads raw of
            [(parsedPort, "")] | validPort parsedPort -> Right parsedPort
            _                                         -> Left $ optionName <> " must be in range 1..65535"

    validPort parsedPort = parsedPort >= (1 :: Int) && parsedPort <= 65535

    parseSSL s = case splitBy ':' s of
        host :| [cert, key] -> Right (host, CertFile cert key)
        _otherwise          -> Left "invalid format for ssl certificates"

    parseRev0 s@('/':_) = do
        (domain, prefix, remote) <- case elemIndices '/' s of
            []      -> Nothing
            indices -> let (prefix, remote) = splitAt (last indices + 1) s
                       in Just (Nothing, BS8.pack prefix, BS8.pack remote)
        if BS8.null remote
        then Nothing
        else Just (domain, prefix, remote)
    parseRev0 remote
      | null remote = Nothing
      | otherwise   = Just (Nothing, "/", BS8.pack remote)

    parseRev ('/':'/':s) = case elemIndex '/' s of
        Nothing  -> Nothing
        Just 0   -> Nothing
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
#ifdef OS_UNIX
                    <*> user
                    <*> group
#endif
#ifdef QUIC_ENABLED
                    <*> quic
#endif

    bind = optional $ strOption
        ( long "bind"
       <> short 'b'
       <> metavar "bind_ip"
       <> help "Specify the IP address to bind to (default: all interfaces)")

    port = option (eitherReader (parseBoundedPort "--port"))
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

#ifdef OS_UNIX
    user = optional $ strOption
        ( long "user"
       <> short 'u'
       <> metavar "nobody"
       <> help "Drop root priviledge and setuid to the specified user (like nobody)")

    group = optional $ strOption
        ( long "group"
       <> short 'g'
       <> metavar "nogroup"
       <> help "Drop root priviledge and setgid to the specified group")
#endif

#ifdef QUIC_ENABLED
    quic = optional $ option (eitherReader (parseBoundedPort "--quic"))
        ( long "quic"
       <> short 'q'
       <> metavar "port"
       <> help "Enable QUIC (HTTP/3) on UDP port")
#endif

-- | Read 'Config' from command line arguments
getConfig :: IO Config
getConfig = execParser parser
