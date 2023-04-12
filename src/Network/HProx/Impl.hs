-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.Impl
  ( ProxySettings (..)
  , forceSSL
  , httpConnectProxy
  , httpGetProxy
  , httpProxy
  , pacProvider
  , reverseProxy
  ) where

import Control.Applicative        ((<|>))
import Control.Concurrent.Async   (concurrently)
import Control.Exception          (SomeException, try)
import Control.Monad              (unless, void, when)
import Control.Monad.IO.Class     (liftIO)
import Data.Binary.Builder        qualified as BB
import Data.ByteString            qualified as BS
import Data.ByteString.Base64     (decodeLenient)
import Data.ByteString.Char8      qualified as BS8
import Data.ByteString.Lazy.Char8 qualified as LBS8
import Data.CaseInsensitive       qualified as CI
import Data.Conduit.Network       qualified as CN
import Network.HTTP.Client        qualified as HC
import Network.HTTP.ReverseProxy
    (ProxyDest (..), SetIpHeader (..), WaiProxyResponse (..),
    defaultWaiProxySettings, waiProxyToSettings, wpsSetIpHeader,
    wpsUpgradeToRaw)
import Network.HTTP.Types         qualified as HT
import Network.HTTP.Types.Header  qualified as HT

import Data.Conduit
import Data.Maybe
import Network.Wai

import Network.HProx.Util

data ProxySettings = ProxySettings
  { proxyAuth  :: Maybe (BS.ByteString -> Bool)
  , passPrompt :: Maybe BS.ByteString
  , wsRemote   :: Maybe BS.ByteString
  , revRemote  :: Maybe BS.ByteString
  }

httpProxy :: ProxySettings -> HC.Manager -> Middleware
httpProxy set mgr = pacProvider . httpGetProxy set mgr . httpConnectProxy set

forceSSL :: ProxySettings -> Middleware
forceSSL pset app req respond
    | isSecure req               = app req respond
    | redirectWebsocket pset req = app req respond
    | otherwise                  = redirectToSSL req respond

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


isProxyHeader :: HT.HeaderName -> Bool
isProxyHeader k = "proxy" `BS.isPrefixOf` CI.foldedCase k

isForwardedHeader :: HT.HeaderName -> Bool
isForwardedHeader k = "x-forwarded" `BS.isPrefixOf` CI.foldedCase k

isToStripHeader :: HT.HeaderName -> Bool
isToStripHeader h = isProxyHeader h || isForwardedHeader h || h == "X-Real-IP" || h == "X-Scheme"

checkAuth :: ProxySettings -> Request -> Bool
checkAuth ProxySettings{..} req
    | isNothing proxyAuth = True
    | isNothing authRsp   = False
    | otherwise           = fromJust proxyAuth decodedRsp
  where
    authRsp = lookup HT.hProxyAuthorization (requestHeaders req)

    decodedRsp = decodeLenient $ snd $ BS8.spanEnd (/=' ') $ fromJust authRsp

redirectWebsocket :: ProxySettings -> Request -> Bool
redirectWebsocket ProxySettings{..} req = wpsUpgradeToRaw defaultWaiProxySettings req && isJust wsRemote

proxyAuthRequiredResponse :: ProxySettings -> Response
proxyAuthRequiredResponse ProxySettings{..} = responseLBS
    HT.status407
    [(HT.hProxyAuthenticate, "Basic realm=\"" `BS.append` prompt `BS.append` "\"")]
    ""
  where
    prompt = fromMaybe "hprox" passPrompt

pacProvider :: Middleware
pacProvider fallback req respond
    | pathInfo req == ["get", "hprox.pac"],
      Just host' <- lookup "x-forwarded-host" (requestHeaders req) <|> requestHeaderHost req =
        let issecure = case lookup "x-forwarded-proto" (requestHeaders req) of
                Just proto -> proto == "https"
                Nothing    -> isSecure req
            scheme = if issecure then "HTTPS" else "PROXY"
            defaultPort = if issecure then ":443" else ":80"
            host | 58 `BS.elem` host' = host' -- ':'
                 | otherwise          = host' `BS.append` defaultPort
        in respond $ responseLBS
               HT.status200
               [("Content-Type", "application/x-ns-proxy-autoconfig")] $
               LBS8.unlines [ "function FindProxyForURL(url, host) {"
                            , LBS8.fromChunks ["  return \"", scheme, " ", host, "\";"]
                            , "}"
                            ]
    | otherwise = fallback req respond

reverseProxy :: ProxySettings -> HC.Manager -> Middleware
reverseProxy ProxySettings{..} mgr fallback
    | isReverseProxy = waiProxyToSettings (return.proxyResponseFor) settings mgr
    | otherwise      = fallback
  where
    settings = defaultWaiProxySettings { wpsSetIpHeader = SIHNone }

    isReverseProxy = isJust revRemote
    (revHost, revPort) = parseHostPortWithDefault 80 (fromJust revRemote)
    revWrapper = if revPort == 443 then WPRModifiedRequestSecure else WPRModifiedRequest

    proxyResponseFor req = revWrapper nreq (ProxyDest revHost revPort)
      where
        nreq = req
          { requestHeaders = hdrs
          , requestHeaderHost = Just revHost
          }

        hdrs = (HT.hHost, revHost) : [ (hdn, hdv)
                                     | (hdn, hdv) <- requestHeaders req
                                     , not (isToStripHeader hdn) && hdn /= HT.hHost
                                     ]

httpGetProxy :: ProxySettings -> HC.Manager -> Middleware
httpGetProxy pset@ProxySettings{..} mgr fallback = waiProxyToSettings (return.proxyResponseFor) settings mgr
  where
    settings = defaultWaiProxySettings { wpsSetIpHeader = SIHNone }

    proxyResponseFor req
        | redirectWebsocket pset req = wsWrapper (ProxyDest wsHost wsPort)
        | not isGetProxy             = WPRApplication fallback
        | checkAuth pset req         = WPRModifiedRequest nreq (ProxyDest host port)
        | otherwise                  = WPRResponse (proxyAuthRequiredResponse pset)
      where
        (wsHost, wsPort) = parseHostPortWithDefault 80 (fromJust wsRemote)
        wsWrapper = if wsPort == 443 then WPRProxyDestSecure else WPRProxyDest

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
            handleConnect False (getRequestBodyChunk req) (\bs -> write (BB.fromByteString bs) >> flush)

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
