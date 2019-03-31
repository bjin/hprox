{-# LANGUAGE OverloadedStrings #-}

module HProx
  ( ProxySettings(..)
  , httpProxy
  , httpGetProxy
  , httpConnectProxy
  , forceSSL
  ) where

import           Control.Applicative       ((<|>))
import           Control.Concurrent.Async  (concurrently)
import           Control.Exception         (SomeException, try)
import           Control.Monad             (unless, void, when)
import           Control.Monad.IO.Class    (liftIO)
import qualified Data.Binary.Builder       as BB
import qualified Data.ByteString           as BS
import           Data.ByteString.Base64    (decodeLenient)
import qualified Data.ByteString.Char8     as BS8
import qualified Data.CaseInsensitive      as CI
import qualified Data.Conduit.Network      as CN
import           Data.Maybe                (fromJust, fromMaybe, isJust,
                                            isNothing)
import qualified Network.HTTP.Client       as HC
import           Network.HTTP.ReverseProxy (ProxyDest (..), SetIpHeader (..),
                                            WaiProxyResponse (..),
                                            defaultWaiProxySettings,
                                            waiProxyToSettings, wpsSetIpHeader,
                                            wpsUpgradeToRaw)
import qualified Network.HTTP.Types        as HT
import qualified Network.HTTP.Types.Header as HT

import           Data.Conduit
import           Network.Wai

data ProxySettings = ProxySettings
  { proxyAuth  :: Maybe (BS.ByteString -> Bool)
  , passPrompt :: Maybe BS.ByteString
  , wsRemote   :: Maybe BS.ByteString
  }

httpProxy :: ProxySettings -> HC.Manager -> Middleware
httpProxy set mgr = httpGetProxy set mgr . httpConnectProxy set

forceSSL :: Middleware
forceSSL app req respond
    | isSecure req = app req respond
    | otherwise    = redirectToSSL req respond

redirectToSSL :: Application
redirectToSSL req respond
    | Just host <- requestHeaderHost req = respond $ responseLBS
        HT.status301
        [("Location", "https://" `BS.append` host)]
        ""
    | otherwise                          = respond $ responseLBS
        (HT.mkStatus 426 "Upgrade Required")
        [("Upgrade", "TLS/1.0, HTTP/1.1"), ("Connection", "Upgrade")]
        ""

parseHostPort :: BS.ByteString -> Maybe (BS.ByteString, Int)
parseHostPort hostPort = do
    lastColon <- BS8.elemIndexEnd ':' hostPort
    port <- BS8.readInt (BS.drop (lastColon+1) hostPort) >>= checkPort
    return (BS.take lastColon hostPort, port)
  where
    checkPort (p, bs)
        | BS.null bs && 1 <= p && p <= 65535 = Just p
        | otherwise                          = Nothing

parseHostPortWithDefault :: Int -> BS.ByteString -> (BS.ByteString, Int)
parseHostPortWithDefault defaultPort hostPort =
    fromMaybe (hostPort, defaultPort) $ parseHostPort hostPort

isProxyHeader :: HT.HeaderName -> Bool
isProxyHeader k
    | BS.length bs <= 4     = False
    | c0 /= 112 && c0 /= 80 = False -- 'p'
    | c1 /= 114 && c1 /= 82 = False -- 'r'
    | c2 /= 111 && c2 /= 79 = False -- 'o'
    | c3 /= 120 && c3 /= 88 = False -- 'x'
    | c4 /= 121 && c4 /= 89 = False -- 'y'
    | otherwise             = True
  where
    bs = CI.original k
    idx = BS.index bs

    c0 = idx 0
    c1 = idx 1
    c2 = idx 2
    c3 = idx 3
    c4 = idx 4

isForwardedHeader :: HT.HeaderName -> Bool
isForwardedHeader k
    | BS.length bs <= 10    = False
    | c0 /= 120 && c0 /= 88 = False -- 'x'
    | c1 /= 45              = False -- '-'
    | c2 /= 102 && c2 /= 70 = False -- 'f'
    | c3 /= 111 && c3 /= 79 = False -- 'o'
    | c4 /= 114 && c4 /= 82 = False -- 'r'
    | c5 /= 119 && c5 /= 87 = False -- 'w'
    | c6 /= 97  && c6 /= 65 = False -- 'a'
    | c7 /= 114 && c7 /= 82 = False -- 'r'
    | c8 /= 100 && c8 /= 68 = False -- 'd'
    | c9 /= 101 && c9 /= 69 = False -- 'e'
    | ca /= 100 && ca /= 68 = False -- 'd'
    | otherwise             = True
  where
    bs = CI.original k
    idx = BS.index bs

    c0 = idx 0
    c1 = idx 1
    c2 = idx 2
    c3 = idx 3
    c4 = idx 4
    c5 = idx 5
    c6 = idx 6
    c7 = idx 7
    c8 = idx 8
    c9 = idx 9
    ca = idx 10

isToStripHeader :: HT.HeaderName -> Bool
isToStripHeader h = isProxyHeader h || isForwardedHeader h || h == "X-Real-IP" || h == "X-Scheme"

checkAuth :: ProxySettings -> Request -> Bool
checkAuth pset req
    | isNothing pauth   = True
    | isNothing authRsp = False
    | otherwise         = fromJust pauth decodedRsp
  where
    pauth = proxyAuth pset
    authRsp = lookup HT.hProxyAuthorization (requestHeaders req)

    decodedRsp = decodeLenient $ snd $ BS8.spanEnd (/=' ') $ fromJust authRsp

proxyAuthRequiredResponse :: ProxySettings -> Response
proxyAuthRequiredResponse pset = responseLBS
    HT.status407
    [(HT.hProxyAuthenticate, "Basic realm=\"" `BS.append` prompt `BS.append` "\"")]
    ""
  where
    prompt = fromMaybe "hprox" (passPrompt pset)

httpGetProxy :: ProxySettings -> HC.Manager -> Middleware
httpGetProxy pset mgr fallback = waiProxyToSettings (return.proxyResponseFor) settings mgr
  where
    settings = defaultWaiProxySettings { wpsSetIpHeader = SIHNone }

    proxyResponseFor req
        | redirectWebsocket  = WPRProxyDest (ProxyDest wsHost wsPort)
        | not isGetProxy     = WPRApplication fallback
        | checkAuth pset req = WPRModifiedRequest nreq (ProxyDest host port)
        | otherwise          = WPRResponse (proxyAuthRequiredResponse pset)
      where
        isWebsocket = wpsUpgradeToRaw defaultWaiProxySettings req
        redirectWebsocket = isWebsocket && isJust (wsRemote pset)
        (wsHost, wsPort) = parseHostPortWithDefault 80 (fromJust (wsRemote pset))

        notCONNECT = requestMethod req /= "CONNECT"
        rawPath = rawPathInfo req
        rawPathPrefix = "http://"
        defaultPort = 80
        hostHeader = parseHostPortWithDefault defaultPort <$> requestHeaderHost req

        isRawPathProxy = rawPathPrefix `BS.isPrefixOf` rawPath
        hasProxyHeader = any (isProxyHeader.fst) (requestHeaders req)
        scheme = lookup "X-Scheme" (requestHeaders req)
        isHTTP2Proxy = HT.httpMajor (httpVersion req) >= 2 && scheme == Just "http" && isSecure req

        isGetProxy = notCONNECT && (isRawPathProxy || isHTTP2Proxy || isJust hostHeader && hasProxyHeader)

        nreq = req
          { rawPathInfo = newRawPath
          , requestHeaders = filter (not.isToStripHeader.fst) $ requestHeaders req
          }

        ((host, port), newRawPath)
            | isRawPathProxy  = (parseHostPortWithDefault defaultPort hostPortP, newRawPathP)
            | otherwise       = (fromJust hostHeader, rawPath)
          where
            (hostPortP, newRawPathP) = BS8.span (/='/') $
                BS.drop (BS.length rawPathPrefix) rawPath

httpConnectProxy :: ProxySettings -> Middleware
httpConnectProxy pset fallback req respond
    | not isConnectProxy = fallback req respond
    | checkAuth pset req = respond response
    | otherwise          = respond (proxyAuthRequiredResponse pset)
  where
    hostPort' = parseHostPort (rawPathInfo req) <|> (requestHeaderHost req >>= parseHostPort)
    isConnectProxy = requestMethod req == "CONNECT" && isJust hostPort'

    Just (host, port) = hostPort'
    settings = CN.clientSettings port host

    backup = responseLBS HT.status500 [("Content-Type", "text/plain")]
        "HTTP CONNECT tunneling detected, but server does not support responseRaw"

    tryAndCatchAll :: IO a -> IO (Either SomeException a)
    tryAndCatchAll = try

    response
        | HT.httpMajor (httpVersion req) < 2 = responseRaw (handleConnect True) backup
        | otherwise                          = responseStream HT.status200 [] streaming
      where
        streaming write flush = do
            flush
            handleConnect False (requestBody req) (\bs -> write (BB.fromByteString bs) >> flush)

    handleConnect :: Bool -> IO BS.ByteString -> (BS.ByteString -> IO ()) -> IO ()
    handleConnect http1 fromClient' toClient' = CN.runTCPClient settings $ \server ->
        let toServer = CN.appSink server
            fromServer = CN.appSource server
            fromClient = do
                bs <- liftIO fromClient'
                unless (BS.null bs) (yield bs >> fromClient)
            toClient = awaitForever (liftIO . toClient')
        in do
            when http1 $ runConduit $ yield "HTTP/1.1 200 OK\r\n\r\n" .| toClient
            void $ tryAndCatchAll $ concurrently
                (runConduit (fromClient .| toServer))
                (runConduit (fromServer .| toClient))
