-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

{-# LANGUAGE ViewPatterns #-}
module Network.HProx.Impl
  ( ProxySettings(..)
  , acmeProvider
  , forceSSL
  , healthCheckProvider
  , httpConnectProxy
  , httpGetProxy
  , httpProxy
  , logRequest
  , pacProvider
  , reverseProxy
  ) where

import Control.Applicative        ((<|>))
import Control.Concurrent.Async   (cancel, wait, waitEither, withAsync)
import Control.Exception          (SomeException, try)
import Control.Monad              (unless, void, when)
import Control.Monad.IO.Class     (liftIO)
import Data.Binary.Builder        qualified as BB
import Data.ByteString            qualified as BS
import Data.ByteString.Base64     (decodeLenient)
import Data.ByteString.Char8      qualified as BS8
import Data.ByteString.Lazy       qualified as LBS
import Data.ByteString.Lazy.Char8 qualified as LBS8
import Data.CaseInsensitive       qualified as CI
import Data.Conduit.Network       qualified as CN
import Data.Text.Encoding         qualified as TE
import Network.HTTP.Client        qualified as HC
import Network.HTTP.ReverseProxy
    (ProxyDest(..), SetIpHeader(..), WaiProxyResponse(..), defaultWaiProxySettings,
    waiProxyToSettings, wpsSetIpHeader, wpsUpgradeToRaw)
import Network.HTTP.Types         qualified as HT
import Network.HTTP.Types.Header  qualified as HT
import System.Timeout             (timeout)

import Data.Conduit
import Data.Maybe
import Network.Wai
import Network.Wai.Middleware.StripHeaders

import Network.HProx.Log
import Network.HProx.Naive
import Network.HProx.Util

data ProxySettings = ProxySettings
  { proxyAuth      :: Maybe (BS.ByteString -> Bool)
  , passPrompt     :: Maybe BS.ByteString
  , wsRemote       :: Maybe BS.ByteString
  , revRemoteMap   :: [(Maybe BS.ByteString, BS.ByteString, BS.ByteString)]
  , hideProxyAuth  :: Bool
  , naivePadding   :: Bool
  , acmeThumbprint :: Maybe BS.ByteString
  , logger         :: Logger
  }

logRequest :: Request -> LogStr
logRequest req = toLogStr (requestMethod req) <>
    " " <> hostname <> toLogStr (rawPathInfo req) <>
    " " <> toLogStr (show $ httpVersion req) <>
    " " <> (if isSecure req then "(tls) " else "")
    <> toLogStr (show $ remoteHost req)
  where
    isConnect = requestMethod req == "CONNECT"
    isGet = "http://" `BS.isPrefixOf` rawPathInfo req
    hostname | isConnect || isGet = ""
             | otherwise          = toLogStr (fromMaybe "(no-host)" $ requestHeaderHost req)

httpProxy :: ProxySettings -> HC.Manager -> Middleware
httpProxy set mgr = pacProvider . httpGetProxy set mgr . httpConnectProxy set

forceSSL :: ProxySettings -> Middleware
forceSSL pset app req respond
    | isSecure req               = app req respond
    | redirectWebsocket pset req = app req respond
    | otherwise                  = redirectToSSL req respond

redirectToSSL :: Application
redirectToSSL req respond
    | Just host <- requestHeaderHost req = respond $ responseKnownLength
        HT.status301
        [("Location", "https://" `BS.append` host)]
        ""
    | otherwise                          = respond $ responseKnownLength
        (HT.mkStatus 426 "Upgrade Required")
        [("Upgrade", "TLS/1.0, HTTP/1.1"), ("Connection", "Upgrade")]
        ""

isProxyHeader :: HT.HeaderName -> Bool
isProxyHeader h = "proxy" `BS.isPrefixOf` CI.foldedCase h

isForwardedHeader :: HT.HeaderName -> Bool
isForwardedHeader h = "x-forwarded" `BS.isPrefixOf` CI.foldedCase h

isCDNHeader :: HT.HeaderName -> Bool
isCDNHeader h = "cf-" `BS.isPrefixOf` CI.foldedCase h || h == "cdn-loop"

isToStripHeader :: HT.HeaderName -> Bool
isToStripHeader h = isProxyHeader h || isForwardedHeader h || isCDNHeader h || h == "X-Real-IP" || h == "X-Scheme"

checkAuth :: ProxySettings -> Request -> Bool
checkAuth ProxySettings{..} req
    | isNothing proxyAuth = True
    | isNothing authRsp   = False
    | otherwise           =
        pureLogger logger TRACE (authMsg <> " request (credential: " <> toLogStr decodedRsp <> ") from " <> toLogStr (show (remoteHost req))) authorized
  where
    authRsp = lookup HT.hProxyAuthorization (requestHeaders req)
    decodedRsp = decodeLenient $ snd $ BS8.spanEnd (/=' ') $ fromJust authRsp

    authorized = fromJust proxyAuth decodedRsp
    authMsg = if authorized then "authorized" else "unauthorized"

parseConnectProxy :: Request -> Maybe (BS.ByteString, Int)
parseConnectProxy req
    | requestMethod req == "CONNECT" = parseHostPort (rawPathInfo req) <|> (requestHeaderHost req >>= parseHostPort)
    | otherwise                      = Nothing

redirectWebsocket :: ProxySettings -> Request -> Bool
redirectWebsocket ProxySettings{..} req = wpsUpgradeToRaw defaultWaiProxySettings req && isJust wsRemote

proxyAuthRequiredResponse :: ProxySettings -> Response
proxyAuthRequiredResponse ProxySettings{..} = responseKnownLength
    HT.status407
    [(HT.hProxyAuthenticate, "Basic realm=\"" `BS.append` prompt `BS.append` "\"")]
    ""
  where
    prompt = fromMaybe "hprox" passPrompt

acmeProvider :: ProxySettings -> Middleware
acmeProvider ProxySettings{..} app req respond
    | not (isSecure req)
    , Just thumbprint <- acmeThumbprint
    , [".well-known", "acme-challenge", token] <- pathInfo req
        = respond $ responseKnownLength
              HT.status200
              [("Content-Type", "text/plain")] $
              LBS.fromChunks [TE.encodeUtf8 token, ".", thumbprint]
    | otherwise
        = app req respond

pacProvider :: Middleware
pacProvider fallback req respond
    | pathInfo req == [".hprox", "config.pac"],
      Just host' <- lookup "x-forwarded-host" (requestHeaders req) <|> requestHeaderHost req =
        let issecure = case lookup "x-forwarded-proto" (requestHeaders req) of
                Just proto -> proto == "https"
                Nothing    -> isSecure req
            scheme = if issecure then "HTTPS" else "PROXY"
            defaultPort = if issecure then ":443" else ":80"
            host | 58 `BS.elem` host' = host' -- ':'
                 | otherwise          = host' `BS.append` defaultPort
        in respond $ responseKnownLength
               HT.status200
               [("Content-Type", "application/x-ns-proxy-autoconfig")] $
               LBS8.unlines [ "function FindProxyForURL(url, host) {"
                            , LBS8.fromChunks ["  return \"", scheme, " ", host, "\";"]
                            , "}"
                            ]
    | otherwise = fallback req respond

healthCheckProvider :: Middleware
healthCheckProvider fallback req respond
    | pathInfo req == [".hprox", "health"] =
        respond $ responseKnownLength
            HT.status200
            [("Content-Type", "text/plain")]
            "okay"
    | otherwise = fallback req respond

reverseProxy :: ProxySettings -> HC.Manager -> Middleware
reverseProxy ProxySettings{..} mgr fallback =
    modifyResponse (stripHeaders ["Server", "Date", "Keep-Alive"]) $
        waiProxyToSettings (return.proxyResponseFor) settings mgr
  where
    settings = defaultWaiProxySettings { wpsSetIpHeader = SIHNone }

    checkDomain Nothing _         = True
    checkDomain _ Nothing         = False
    checkDomain (Just a) (Just b) = a == b

    proxyResponseFor req = go revRemoteMap
      where
        go ((mTargetHost, prefix, revRemote):left)
          | checkDomain mTargetHost mReqHost && prefix `BS.isPrefixOf` rawPathInfo req =
            if revPort == 443
                then WPRModifiedRequestSecure nreq (ProxyDest revHost revPort)
                else WPRModifiedRequest nreq (ProxyDest revHost revPort)
          | otherwise = go left
          where
            mReqHost = fmap (fst . parseHostPortWithDefault (error "unused port number")) (requestHeaderHost req)
            (revHost, revPort) = parseHostPortWithDefault 80 revRemote
            nreq = req
              { requestHeaders = hdrs
              , requestHeaderHost = Just revHost
              , rawPathInfo = BS.drop (BS.length prefix - 1) (rawPathInfo req)
              }
            hdrs = (HT.hHost, revHost) : [ (hdn, hdv)
                                         | (hdn, hdv) <- requestHeaders req
                                         , not (isToStripHeader hdn) && hdn /= HT.hHost
                                         ]
        go _ = WPRApplication fallback

httpGetProxy :: ProxySettings -> HC.Manager -> Middleware
httpGetProxy pset@ProxySettings{..} mgr fallback = waiProxyToSettings (return.proxyResponseFor) settings mgr
  where
    settings = defaultWaiProxySettings { wpsSetIpHeader = SIHNone }

    proxyResponseFor req
        | redirectWebsocket pset req = wsWrapper (ProxyDest wsHost wsPort)
        | not isGETProxy             = WPRApplication fallback
        | checkAuth pset req         = WPRModifiedRequest nreq (ProxyDest host port)
        | hideProxyAuth              =
            pureLogger logger WARN ("unauthorized request (hidden without response): " <> logRequest req) $
            WPRApplication fallback
        | otherwise                  =
            pureLogger logger WARN ("unauthorized request: " <> logRequest req) $
            WPRResponse (proxyAuthRequiredResponse pset)
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

        isGETProxy = notCONNECT && (isRawPathProxy || isHTTP2Proxy || isJust hostHeader && hasProxyHeader)

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
httpConnectProxy pset@ProxySettings{..} fallback req@(parseConnectProxy -> Just (host, port)) respond
    | checkAuth pset req = do
        when (isJust mPaddingType) $ logger DEBUG $ "naiveproxy padding type detected: " <> toLogStr (show (fromJust mPaddingType)) <> " for " <> logRequest req
        respondResponse
    | hideProxyAuth      = do
        logger WARN $ "unauthorized request (hidden without response): " <> logRequest req
        fallback req respond
    | otherwise          = do
        logger WARN $ "unauthorized request: " <> logRequest req
        respond (proxyAuthRequiredResponse pset)
  where
    settings = CN.clientSettings port host

    backup = responseKnownLength HT.status500 [("Content-Type", "text/plain")]
        "HTTP CONNECT tunneling detected, but server does not support responseRaw"

    tryAndCatchAll :: IO a -> IO (Either SomeException a)
    tryAndCatchAll = try

    runStreams :: Int -> IO () -> IO () -> IO (Either SomeException ())
    runStreams secs left right = tryAndCatchAll $
        withAsync left $ \l -> do
            withAsync right $ \r -> do
                res1 <- waitEither l r
                let unfinished = case res1 of
                        Left _  -> r
                        Right _ -> l
                res2 <- timeout (secs * 1000000) (wait unfinished)
                when (isNothing res2) $ cancel unfinished

    mPaddingType = if naivePadding then parseRequestForPadding req else Nothing

    respondResponse
        | HT.httpMajor (httpVersion req) < 2 = respond $ responseRaw (handleConnect True) backup
        | otherwise                          = do
            paddingHeaders <- liftIO $ prepareResponseForPadding mPaddingType
            respond $ responseStream HT.status200 paddingHeaders streaming
      where
        streaming write flush = do
            flush
            handleConnect False (getRequestBodyChunk req) (\bs -> write (BB.fromByteString bs) >> flush)

    yieldHttp1Response = do
        paddingHeaders <- liftIO $ prepareResponseForPadding mPaddingType
        let headers = [ BB.fromByteString (CI.original hn) <> ": " <> BB.fromByteString hv <> "\r\n"
                      | (hn, hv) <- paddingHeaders
                      ]
        yield $ LBS.toStrict $ BB.toLazyByteString ("HTTP/1.1 200 OK\r\n" <> mconcat headers <> "\r\n")

    handleConnect :: Bool -> IO BS.ByteString -> (BS.ByteString -> IO ()) -> IO ()
    handleConnect http1 fromClient' toClient' = CN.runTCPClient settings $ \server ->
        let toServer = CN.appSink server
            fromServer = CN.appSource server
            fromClient = do
                bs <- liftIO fromClient'
                unless (BS.null bs) (yield bs >> fromClient)
            toClient = awaitForever (liftIO . toClient')

            clientToServer | Just padding <- mPaddingType = fromClient .| removePaddingConduit padding .| toServer
                           | otherwise                    = fromClient .| toServer

            serverToClient | Just padding <- mPaddingType = fromServer .| addPaddingConduit padding .| toClient
                           | otherwise                    = fromServer .| toClient
        in do
            when http1 $ runConduit $ yieldHttp1Response .| toClient
            -- gracefully close the other stream after 5 seconds if one side of stream is closed.
            void $ runStreams 5
                (runConduit clientToServer)
                (runConduit serverToClient)
httpConnectProxy _ fallback req respond = fallback req respond
